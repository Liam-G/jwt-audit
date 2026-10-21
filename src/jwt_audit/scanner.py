"""Active JWT scanner with discovery, confirmation, and bounded concurrency."""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from .models import Finding, ScanReport
from .profiles import PROFILES, ScanProfile
from .tokens import (
    SecretCandidate,
    TokenCandidate,
    build_payloads,
    candidate_count,
    default_payloads,
    generate_candidates,
)

DENIED_STATUSES = frozenset({401, 403})
DEFAULT_DENIAL_PATTERNS = (
    "unauthorized",
    "not authorized",
    "access denied",
    "forbidden",
    "invalid token",
    "invalid credentials",
    "authentication required",
    "not authenticated",
    "credenziali di accesso non valide",
)
LOGIN_MARKERS = ("login", "signin", "sign-in", "authenticate", "unauthorized", "forbidden")
RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})


class ConfigurationError(ValueError):
    """Raised when a scan configuration is invalid."""


class ScanLimitReached(RuntimeError):
    """Raised internally when a configured request or runtime budget is exhausted."""


@dataclass(frozen=True)
class ProtectedEndpoint:
    endpoint: str
    method: str
    status: int


def normalize_target(target: str, *, allow_insecure_http: bool = False) -> str:
    target = target.strip()
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError("target must not contain credentials, a query, or a fragment")
    if parsed.scheme == "http" and not allow_insecure_http:
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ConfigurationError(
                "plain HTTP is limited to loopback; use --allow-insecure-http when authorized"
            )
    return target.rstrip("/") + "/"


def normalize_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if not endpoint.startswith("/") or endpoint.startswith("//"):
        raise ConfigurationError(f"endpoint must be an absolute path: {endpoint!r}")
    parsed = urlsplit(endpoint)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ConfigurationError(
            f"endpoint must not contain a URL, query, or fragment: {endpoint!r}"
        )
    return endpoint


def _secret_fingerprint(secret: str) -> str:
    return f"sha256:{hashlib.sha256(secret.encode()).hexdigest()[:12]}"


def _same_origin(left: str, right: str) -> bool:
    first, second = urlsplit(left), urlsplit(right)
    return (first.scheme, first.hostname, first.port) == (
        second.scheme,
        second.hostname,
        second.port,
    )


class Scanner:
    """Discover protected endpoints and test forged JWT candidates."""

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        delay: float = 0.25,
        rate: float | None = None,
        retries: int = 1,
        backoff: float = 0.5,
        max_requests: int = 10_000,
        max_runtime: float = 600.0,
        max_candidates: int = 5_000,
        max_endpoints: int = 500,
        workers: int | None = None,
        user_agent: str = "jwt-audit/0.3 (+authorized-security-testing)",
        denial_patterns: Iterable[str] = (),
        headers: dict[str, str] | None = None,
        proxy: str | None = None,
        verify_tls: bool = True,
        token_cookie: str | None = None,
        session: requests.Session | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        if timeout <= 0:
            raise ConfigurationError("timeout must be greater than zero")
        if delay < 0:
            raise ConfigurationError("delay cannot be negative")
        if rate is not None and rate <= 0:
            raise ConfigurationError("rate must be greater than zero")
        if not 0 <= retries <= 10:
            raise ConfigurationError("retries must be between 0 and 10")
        if backoff < 0 or backoff > 60:
            raise ConfigurationError("backoff must be between 0 and 60 seconds")
        if max_requests < 1:
            raise ConfigurationError("max-requests must be greater than zero")
        if max_runtime <= 0:
            raise ConfigurationError("max-runtime must be greater than zero")
        if max_candidates < 1:
            raise ConfigurationError("max-candidates must be greater than zero")
        if max_endpoints < 1:
            raise ConfigurationError("max-endpoints must be greater than zero")
        if workers is not None and not 1 <= workers <= 32:
            raise ConfigurationError("workers must be between 1 and 32")
        self.timeout = timeout
        self.delay = delay
        self.rate = rate
        self.retries = retries
        self.backoff = backoff
        self.max_requests = max_requests
        self.max_runtime = max_runtime
        self.max_candidates = max_candidates
        self.max_endpoints = max_endpoints
        self.workers = workers
        self.user_agent = user_agent
        self.headers = dict(headers or {})
        if any(key.lower() == "authorization" for key in self.headers):
            raise ConfigurationError("custom Authorization headers are not supported")
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.token_cookie = token_cookie
        if any(not pattern.strip() for pattern in denial_patterns):
            raise ConfigurationError("denial patterns cannot be empty")
        self.denial_patterns = tuple(
            dict.fromkeys((*DEFAULT_DENIAL_PATTERNS, *(p.lower() for p in denial_patterns)))
        )
        self._injected_session = session
        self._sleep = sleeper
        self._progress = progress or (lambda _: None)
        self._counter_lock = threading.RLock()
        self.requests_sent = 0
        self._deadline: float | None = None
        self._next_request_at = 0.0
        self._limit_reason: str | None = None

    def _limit(self, reason: str) -> ScanLimitReached:
        with self._counter_lock:
            if self._limit_reason is None:
                self._limit_reason = reason
        return ScanLimitReached(reason)

    def _acquire_request_slot(self) -> None:
        """Reserve one request from the global budget and apply global pacing."""
        with self._counter_lock:
            now = time.monotonic()
            if self._deadline is not None and now >= self._deadline:
                raise self._limit(f"maximum runtime of {self.max_runtime:g}s reached")
            if self.requests_sent >= self.max_requests:
                raise self._limit(f"maximum request budget of {self.max_requests} reached")
            interval = 1.0 / self.rate if self.rate is not None else 0.0
            scheduled = max(now, self._next_request_at)
            if self._deadline is not None and scheduled + self.delay >= self._deadline:
                raise self._limit(f"maximum runtime of {self.max_runtime:g}s reached")
            self._next_request_at = scheduled + interval
            self.requests_sent += 1
        wait = max(0.0, scheduled - time.monotonic()) + self.delay
        if wait:
            self._sleep(wait)

    def _retry_delay(self, response: requests.Response | None, attempt: int) -> float:
        value = str(response.headers.get("Retry-After", "")) if response is not None else ""
        if value:
            try:
                return min(60.0, max(0.0, float(value)))
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(value)
                    return min(60.0, max(0.0, parsed.timestamp() - time.time()))
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(60.0, self.backoff * float(2**attempt))

    def _session(self) -> requests.Session:
        if self._injected_session is not None:
            return self._injected_session
        session = requests.Session()
        session.headers.update({"User-Agent": self.user_agent, **self.headers})
        if self.proxy:
            session.proxies.update({"http": self.proxy, "https": self.proxy})
        return session

    def _request(
        self,
        session: requests.Session,
        method: str,
        url: str,
        *,
        token: str | None = None,
    ) -> requests.Response:
        headers = {"Authorization": f"Bearer {token}"} if token and not self.token_cookie else None
        cookies = {self.token_cookie: token} if token and self.token_cookie else None
        last_error: requests.RequestException | None = None
        for attempt in range(self.retries + 1):
            self._acquire_request_slot()
            try:
                response = session.request(
                    method,
                    url,
                    headers=headers,
                    cookies=cookies,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=self.verify_tls,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_error = exc
                if attempt >= self.retries:
                    raise
                self._sleep(self._retry_delay(None, attempt))
                continue
            if response.status_code not in RETRYABLE_STATUSES or attempt >= self.retries:
                return response
            self._sleep(self._retry_delay(response, attempt))
        assert last_error is not None  # pragma: no cover - loop always returns or raises
        raise last_error

    def _denied(self, response: requests.Response) -> bool:
        if response.status_code in DENIED_STATUSES:
            return True
        location = response.headers.get("Location", "").lower()
        if 300 <= response.status_code < 400 and any(
            marker in location for marker in LOGIN_MARKERS
        ):
            return True
        body = response.text[:8192].lower()
        return any(pattern in body for pattern in self.denial_patterns)

    def _follow_candidate(
        self,
        session: requests.Session,
        method: str,
        initial_url: str,
        response: requests.Response,
        token: str,
    ) -> tuple[requests.Response, str]:
        current_url = initial_url
        current = response
        for _ in range(3):
            if not 300 <= current.status_code < 400:
                break
            location = current.headers.get("Location")
            if not location:
                break
            if any(marker in location.lower() for marker in LOGIN_MARKERS):
                break
            next_url = urljoin(current_url, location)
            if not _same_origin(initial_url, next_url):
                break
            current_url = next_url
            current = self._request(session, method, current_url, token=token)
        return current, current_url

    def _discover(
        self,
        session: requests.Session,
        target: str,
        endpoints: tuple[str, ...],
        profile: ScanProfile,
        errors: list[str],
    ) -> tuple[list[ProtectedEndpoint], int]:
        protected: list[ProtectedEndpoint] = []
        tested = 0
        for endpoint in endpoints:
            url = urljoin(target, endpoint.lstrip("/"))
            try:
                for method_index, method in enumerate(profile.methods):
                    baseline = self._request(session, method, url)
                    if method_index == 0:
                        tested += 1
                    if self._denied(baseline):
                        protected.append(ProtectedEndpoint(endpoint, method, baseline.status_code))
                        break
                    if baseline.status_code != 405:
                        break
            except ScanLimitReached:
                break
            except requests.RequestException as exc:
                errors.append(f"{target.rstrip('/')}{endpoint}: {type(exc).__name__}: {exc}")
        return protected, tested

    def _candidate_finding(
        self,
        *,
        target: str,
        protected: ProtectedEndpoint,
        candidate: TokenCandidate,
        response: requests.Response,
        final_url: str,
    ) -> Finding:
        secret = candidate.secret
        attack_class = candidate.attack_class
        return Finding(
            target=target.rstrip("/"),
            endpoint=protected.endpoint,
            method=protected.method,
            baseline_status=protected.status,
            authenticated_status=response.status_code,
            algorithm=candidate.algorithm,
            header_variant=candidate.header_variant,
            payload=candidate.payload,
            candidate_label=candidate.label,
            secret_fingerprint=_secret_fingerprint(secret.value) if secret else None,
            redirected_to=final_url
            if final_url != urljoin(target, protected.endpoint.lstrip("/"))
            else None,
            title=(
                {
                    "unsigned": "Unsigned JWT was accepted",
                    "algorithm-manipulation": "JWT algorithm-manipulation candidate was accepted",
                    "algorithm-confusion": "RSA/HMAC algorithm-confusion candidate was accepted",
                    "key-edge-case": "JWT signed with an empty/null key was accepted",
                    "weak-hmac-key": "JWT signed with a weak candidate secret was accepted",
                }[attack_class]
            ),
            severity="critical"
            if attack_class in {"unsigned", "algorithm-manipulation", "algorithm-confusion"}
            else "high",
            vulnerability_class=attack_class,
        )

    def _scan_target(
        self,
        target: str,
        endpoints: tuple[str, ...],
        secrets: tuple[SecretCandidate, ...],
        profile: ScanProfile,
        custom_payloads: tuple[dict[str, Any], ...],
        include_builtin_payloads: bool,
    ) -> tuple[list[Finding], int, int, list[str]]:
        session = self._session()
        errors: list[str] = []
        protected, endpoints_tested = self._discover(session, target, endpoints, profile, errors)
        self._progress(f"{target.rstrip('/')}: {len(protected)} protected endpoint(s)")
        host = urlsplit(target).hostname or "target"
        builtins: tuple[dict[str, Any], ...] = ()
        if include_builtin_payloads:
            builtins = (
                default_payloads()
                if profile.name == "safe"
                else build_payloads(host, deep=profile.deep_payloads)
            )
        payloads = (*builtins, *custom_payloads)
        candidates = generate_candidates(
            payloads,
            secrets,
            algorithms=profile.algorithms,
            header_variants=profile.header_variants,
            include_unsigned=profile.include_unsigned,
            include_key_edge_cases=profile.include_key_edge_cases,
            include_algorithm_mutations=profile.include_algorithm_mutations,
            limit=self.max_candidates,
        )
        findings: list[Finding] = []
        for item in protected:
            url = urljoin(target, item.endpoint.lstrip("/"))
            found_classes: set[str] = set()
            for candidate in candidates:
                finding_class = candidate.attack_class
                if finding_class in found_classes:
                    continue
                try:
                    response = self._request(session, item.method, url, token=candidate.token)
                    final_url = url
                    if profile.follow_same_origin_redirects and 300 <= response.status_code < 400:
                        response, final_url = self._follow_candidate(
                            session, item.method, url, response, candidate.token
                        )
                    if not 200 <= response.status_code < 300 or self._denied(response):
                        continue
                    if final_url != url:
                        redirected_baseline = self._request(session, item.method, final_url)
                        if not self._denied(redirected_baseline):
                            continue
                    confirmation = self._request(session, item.method, url)
                    if not self._denied(confirmation):
                        continue
                    findings.append(
                        self._candidate_finding(
                            target=target,
                            protected=item,
                            candidate=candidate,
                            response=response,
                            final_url=final_url,
                        )
                    )
                    found_classes.add(finding_class)
                    self._progress(f"finding: {item.method} {url} accepted {candidate.algorithm}")
                    expected: set[str] = set()
                    if any(secret.kind == "secret" for secret in secrets):
                        expected.add("weak-hmac-key")
                    if profile.include_unsigned:
                        expected.add("unsigned")
                    if profile.include_key_edge_cases:
                        expected.add("key-edge-case")
                    if profile.include_algorithm_mutations:
                        expected.add("algorithm-manipulation")
                    if any(secret.kind == "confusion-key" for secret in secrets):
                        expected.add("algorithm-confusion")
                    if found_classes == expected:
                        break
                except ScanLimitReached:
                    return findings, len(protected), endpoints_tested, errors
                except requests.RequestException as exc:
                    errors.append(f"{url}: {type(exc).__name__}: {exc}")
                    break
        return findings, len(protected), endpoints_tested, errors

    def scan(
        self,
        *,
        targets: Iterable[str],
        endpoints: Iterable[str] = (),
        secrets: Iterable[str | SecretCandidate] = (),
        profile: str = "standard",
        allow_insecure_http: bool = False,
        methods: Iterable[str] = (),
        algorithms: Iterable[str] = (),
        header_variants: Iterable[str] = (),
        include_unsigned: bool | None = None,
        include_key_edge_cases: bool | None = None,
        include_algorithm_mutations: bool | None = None,
        include_builtin_endpoints: bool = True,
        payloads: Iterable[dict[str, Any]] = (),
        include_builtin_payloads: bool = True,
    ) -> ScanReport:
        if profile not in PROFILES:
            raise ConfigurationError(f"unknown profile: {profile}")
        selected = PROFILES[profile]
        clean_methods = tuple(dict.fromkeys(method.upper() for method in methods))
        if any(method not in ALLOWED_METHODS for method in clean_methods):
            raise ConfigurationError("unsupported HTTP method")
        clean_algorithms = tuple(dict.fromkeys(algorithm.upper() for algorithm in algorithms))
        if any(algorithm not in {"HS256", "HS384", "HS512"} for algorithm in clean_algorithms):
            raise ConfigurationError("unsupported HMAC algorithm")
        clean_variants = tuple(dict.fromkeys(header_variants))
        if any(variant not in {"library", "alg-first", "typ-first"} for variant in clean_variants):
            raise ConfigurationError("unsupported JWT header variant")
        selected = replace(
            selected,
            methods=clean_methods or selected.methods,
            algorithms=clean_algorithms or selected.algorithms,
            header_variants=clean_variants or selected.header_variants,
            include_unsigned=(
                selected.include_unsigned if include_unsigned is None else include_unsigned
            ),
            include_key_edge_cases=(
                selected.include_key_edge_cases
                if include_key_edge_cases is None
                else include_key_edge_cases
            ),
            include_algorithm_mutations=(
                selected.include_algorithm_mutations
                if include_algorithm_mutations is None
                else include_algorithm_mutations
            ),
        )
        clean_targets = tuple(
            dict.fromkeys(
                normalize_target(target, allow_insecure_http=allow_insecure_http)
                for target in targets
            )
        )
        custom_endpoints = tuple(normalize_endpoint(endpoint) for endpoint in endpoints)
        built_in_endpoints = selected.endpoints if include_builtin_endpoints else ()
        clean_endpoints = tuple(dict.fromkeys((*custom_endpoints, *built_in_endpoints)))
        if len(clean_endpoints) > self.max_endpoints:
            raise ConfigurationError(
                f"endpoint count {len(clean_endpoints)} exceeds "
                f"--max-endpoints {self.max_endpoints}"
            )
        clean_payloads = tuple(payloads)
        clean_secrets: list[SecretCandidate] = []
        for index, secret in enumerate(secrets, start=1):
            if isinstance(secret, SecretCandidate):
                if secret.value.strip():
                    clean_secrets.append(secret)
            elif secret.strip():
                clean_secrets.append(SecretCandidate(secret.strip(), f"candidate:{index}"))
        if not clean_targets:
            raise ConfigurationError("at least one target is required")
        if not clean_endpoints:
            raise ConfigurationError("at least one endpoint is required")
        if not clean_secrets and not (
            selected.include_unsigned
            or selected.include_key_edge_cases
            or selected.include_algorithm_mutations
        ):
            raise ConfigurationError("at least one candidate secret or keyless attack is required")
        if not include_builtin_payloads and not clean_payloads:
            raise ConfigurationError("at least one payload is required")

        self.requests_sent = 0
        self._limit_reason = None
        self._next_request_at = 0.0
        self._deadline = time.monotonic() + self.max_runtime

        findings: list[Finding] = []
        errors: list[str] = []
        protected_total = 0
        endpoints_tested = 0
        worker_count = min(self.workers or selected.workers, len(clean_targets))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            jobs = {
                executor.submit(
                    self._scan_target,
                    target,
                    clean_endpoints,
                    tuple(clean_secrets),
                    selected,
                    clean_payloads,
                    include_builtin_payloads,
                ): target
                for target in clean_targets
            }
            for future in as_completed(jobs):
                try:
                    target_findings, protected_count, tested_count, target_errors = future.result()
                    findings.extend(target_findings)
                    protected_total += protected_count
                    endpoints_tested += tested_count
                    errors.extend(target_errors)
                except Exception as exc:  # pragma: no cover - defensive worker boundary
                    errors.append(f"{jobs[future]}: {type(exc).__name__}: {exc}")
        notes: list[str] = []
        if self._limit_reason:
            notes.append(f"scan stopped early: {self._limit_reason}")
        base_payload_count = (
            len(default_payloads())
            if profile == "safe"
            else len(build_payloads("target", deep=selected.deep_payloads))
        )
        payload_count = len(clean_payloads) + (
            base_payload_count if include_builtin_payloads else 0
        )
        uncapped_candidate_count = candidate_count(
            payload_count,
            len(clean_secrets),
            algorithms=selected.algorithms,
            header_variants=selected.header_variants,
            include_unsigned=selected.include_unsigned,
            include_key_edge_cases=selected.include_key_edge_cases,
            include_algorithm_mutations=selected.include_algorithm_mutations,
        )
        if uncapped_candidate_count > self.max_candidates:
            notes.append(
                f"candidate set truncated from {uncapped_candidate_count} "
                f"to {self.max_candidates}; "
                "raise --max-candidates to test the remainder"
            )
        return ScanReport.create(
            targets_scanned=len(clean_targets),
            endpoints_tested=endpoints_tested,
            protected_endpoints=protected_total,
            requests_sent=self.requests_sent,
            findings=findings,
            errors=errors,
            notes=notes,
            profile=profile,
        )
