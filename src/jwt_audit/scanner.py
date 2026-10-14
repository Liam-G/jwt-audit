"""Core scanner with conservative defaults and redacted reporting."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Iterable
from urllib.parse import urljoin, urlsplit

import requests

from .models import Finding, ScanReport
from .tokens import default_payloads, encode_candidate

DENIED_STATUSES = frozenset({401, 403})


class ConfigurationError(ValueError):
    """Raised when a scan configuration violates a safety invariant."""


def normalize_target(target: str, *, allow_insecure_http: bool = False) -> str:
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


class Scanner:
    """Compare unauthenticated responses with candidate-token responses."""

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        delay: float = 0.25,
        user_agent: str = "jwt-audit/0.1 (+authorized-security-testing)",
        session: requests.Session | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout <= 0:
            raise ConfigurationError("timeout must be greater than zero")
        if delay < 0:
            raise ConfigurationError("delay cannot be negative")
        self.timeout = timeout
        self.delay = delay
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self._sleep = sleeper
        self.requests_sent = 0

    def _get(self, url: str, *, token: str | None = None) -> requests.Response:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        self._sleep(self.delay)
        self.requests_sent += 1
        return self.session.get(
            url,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=False,
        )

    def scan(
        self,
        *,
        targets: Iterable[str],
        endpoints: Iterable[str],
        secrets: Iterable[str],
        allow_insecure_http: bool = False,
    ) -> ScanReport:
        clean_targets = [
            normalize_target(target, allow_insecure_http=allow_insecure_http) for target in targets
        ]
        clean_endpoints = [normalize_endpoint(endpoint) for endpoint in endpoints]
        clean_secrets = [secret.strip() for secret in secrets if secret.strip()]
        if not clean_targets:
            raise ConfigurationError("at least one target is required")
        if not clean_endpoints:
            raise ConfigurationError("at least one endpoint is required")
        if not clean_secrets:
            raise ConfigurationError("at least one candidate secret is required")

        findings: list[Finding] = []
        for target in clean_targets:
            for endpoint in clean_endpoints:
                url = urljoin(target, endpoint.lstrip("/"))
                baseline = self._get(url)
                if baseline.status_code not in DENIED_STATUSES:
                    continue

                found = False
                for secret in clean_secrets:
                    for payload in default_payloads():
                        response = self._get(url, token=encode_candidate(payload, secret))
                        if 200 <= response.status_code < 300:
                            findings.append(
                                Finding(
                                    target=target.rstrip("/"),
                                    endpoint=endpoint,
                                    method="GET",
                                    baseline_status=baseline.status_code,
                                    authenticated_status=response.status_code,
                                    secret_fingerprint=_secret_fingerprint(secret),
                                    payload=payload,
                                )
                            )
                            found = True
                            break
                    if found:
                        break

        return ScanReport.create(
            targets_scanned=len(clean_targets),
            requests_sent=self.requests_sent,
            findings=findings,
        )
