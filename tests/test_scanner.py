from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from jwt_audit.profiles import PROFILES
from jwt_audit.scanner import ConfigurationError, Scanner, normalize_endpoint, normalize_target


class FakeResponse:
    def __init__(
        self, status_code: int, *, text: str = "", headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.headers: dict[str, str] = {}
        self._responses: Iterator[FakeResponse] = iter(responses)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        return next(self._responses)


def test_normalizers_reject_ambiguous_scope() -> None:
    assert normalize_target("https://example.test/api") == "https://example.test/api/"
    assert normalize_target("http://localhost:8000") == "http://localhost:8000/"
    with pytest.raises(ConfigurationError):
        normalize_target("http://example.test")
    for endpoint in ("users", "//evil.test/path", "/x?q=1"):
        with pytest.raises(ConfigurationError):
            normalize_endpoint(endpoint)


def test_configuration_invariants() -> None:
    with pytest.raises(ConfigurationError):
        Scanner(timeout=0)
    with pytest.raises(ConfigurationError):
        Scanner(delay=-1)
    with pytest.raises(ConfigurationError):
        Scanner(workers=33)
    with pytest.raises(ConfigurationError):
        Scanner(headers={"Authorization": "Bearer existing"})
    with pytest.raises(ConfigurationError):
        Scanner(denial_patterns=[""])
    for options in (
        {"rate": 0},
        {"retries": 11},
        {"backoff": -1},
        {"max_requests": 0},
        {"max_runtime": 0},
        {"max_candidates": 0},
        {"max_endpoints": 0},
    ):
        with pytest.raises(ConfigurationError):
            Scanner(**options)  # type: ignore[arg-type]
    scanner = Scanner(delay=0, sleeper=lambda _: None)
    with pytest.raises(ConfigurationError):
        scanner.scan(targets=[], profile="safe")
    with pytest.raises(ConfigurationError):
        scanner.scan(targets=["https://example.test"], profile="unknown")
    with pytest.raises(ConfigurationError):
        scanner.scan(targets=["https://example.test"], profile="safe")
    with pytest.raises(ConfigurationError):
        scanner.scan(targets=["https://example.test"], endpoints=["/admin"], profile="safe")


def test_scanner_confirms_accepted_candidate_and_redacts_secret() -> None:
    session = FakeSession([FakeResponse(401), FakeResponse(200), FakeResponse(401)])
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    report = scanner.scan(
        targets=["https://example.test"],
        endpoints=["/api/me"],
        secrets=["weak-secret"],
        profile="safe",
    )
    assert report.requests_sent == 3
    assert report.protected_endpoints == 1
    assert len(report.findings) == 1
    assert report.findings[0].algorithm == "HS256"
    assert "weak-secret" not in str(report.as_dict())
    assert all(call[2]["allow_redirects"] is False for call in session.calls)


def test_public_endpoint_is_not_attacked() -> None:
    session = FakeSession([FakeResponse(200)])
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    report = scanner.scan(
        targets=["https://example.test"],
        endpoints=["/health"],
        secrets=["candidate"],
        profile="safe",
    )
    assert not report.findings
    assert report.requests_sent == 1


def test_denial_body_and_post_fallback_discovery() -> None:
    session = FakeSession(
        [FakeResponse(200, text="invalid token"), FakeResponse(405), FakeResponse(403)]
    )
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    errors: list[str] = []
    found, tested = scanner._discover(  # noqa: SLF001
        session,  # type: ignore[arg-type]
        "https://example.test/",
        ("/body-denial", "/post-only"),
        PROFILES["standard"],
        errors,
    )
    assert [(item.endpoint, item.method) for item in found] == [
        ("/body-denial", "GET"),
        ("/post-only", "POST"),
    ]
    assert tested == 2


def test_deep_profile_reports_unsigned_acceptance() -> None:
    session = FakeSession([FakeResponse(401), FakeResponse(200), FakeResponse(401)])
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    findings, protected, tested, errors = scanner._scan_target(  # noqa: SLF001
        "https://example.test/", ("/admin",), (), PROFILES["deep"], (), True
    )
    assert protected == 1
    assert tested == 1
    assert not errors
    assert [finding.algorithm for finding in findings] == ["none"]


def test_redirects_are_limited_to_non_login_same_origin_locations() -> None:
    scanner = Scanner(delay=0, sleeper=lambda _: None)
    login_session = FakeSession([])
    login = FakeResponse(302, headers={"Location": "/login"})
    response, final_url = scanner._follow_candidate(  # noqa: SLF001
        login_session,  # type: ignore[arg-type]
        "GET",
        "https://example.test/admin",
        login,  # type: ignore[arg-type]
        "token",
    )
    assert response is login
    assert final_url == "https://example.test/admin"
    assert not login_session.calls

    redirect_session = FakeSession([FakeResponse(200)])
    dashboard = FakeResponse(302, headers={"Location": "/dashboard"})
    response, final_url = scanner._follow_candidate(  # noqa: SLF001
        redirect_session,  # type: ignore[arg-type]
        "GET",
        "https://example.test/admin",
        dashboard,  # type: ignore[arg-type]
        "token",
    )
    assert response.status_code == 200
    assert final_url == "https://example.test/dashboard"


def test_cookie_transport_does_not_send_authorization_header() -> None:
    session = FakeSession([FakeResponse(401)])
    transport_name = "access_token"
    candidate_value = "candidate"
    scanner = Scanner(session=session, token_cookie=transport_name, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    scanner._request(  # type: ignore[arg-type]  # noqa: SLF001
        session, "GET", "https://example.test/me", token=candidate_value
    )
    options = session.calls[0][2]
    assert options["headers"] is None
    assert options["cookies"] == {"access_token": "candidate"}


def test_request_budget_stops_scan_and_reports_partial_results() -> None:
    session = FakeSession([FakeResponse(401), FakeResponse(200)])
    scanner = Scanner(  # type: ignore[arg-type]
        session=session, max_requests=2, delay=0, sleeper=lambda _: None
    )
    report = scanner.scan(
        targets=["https://example.test"],
        endpoints=["/me"],
        secrets=["secret"],
        profile="safe",
    )
    assert report.requests_sent == 2
    assert not report.findings
    assert "maximum request budget" in report.notes[0]


def test_retryable_response_uses_retry_after_and_counts_attempts() -> None:
    session = FakeSession([FakeResponse(429, headers={"Retry-After": "2"}), FakeResponse(401)])
    sleeps: list[float] = []
    scanner = Scanner(  # type: ignore[arg-type]
        session=session, retries=1, delay=0, sleeper=sleeps.append
    )
    response = scanner._request(session, "GET", "https://example.test/me")  # noqa: SLF001
    assert response.status_code == 401
    assert scanner.requests_sent == 2
    assert sleeps == [2.0]


def test_explicit_method_override_is_used() -> None:
    session = FakeSession([FakeResponse(200)])
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    scanner.scan(
        targets=["https://example.test"],
        endpoints=["/me"],
        secrets=["secret"],
        profile="safe",
        methods=["PATCH"],
    )
    assert session.calls[0][0] == "PATCH"


def test_candidate_cap_is_reported() -> None:
    session = FakeSession([FakeResponse(200)])
    scanner = Scanner(  # type: ignore[arg-type]
        session=session, max_candidates=1, delay=0, sleeper=lambda _: None
    )
    report = scanner.scan(
        targets=["https://example.test"],
        endpoints=["/me"],
        secrets=["one", "two"],
        profile="safe",
    )
    assert "candidate set truncated" in report.notes[0]
