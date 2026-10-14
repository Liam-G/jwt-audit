from __future__ import annotations

from typing import Any

import pytest

from jwt_audit.scanner import ConfigurationError, Scanner, normalize_endpoint, normalize_target


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeSession:
    def __init__(self, statuses: list[int]) -> None:
        self.headers: dict[str, str] = {}
        self._statuses = iter(statuses)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        return FakeResponse(next(self._statuses))


def test_normalize_target_requires_https_except_loopback() -> None:
    assert normalize_target("https://example.test/api") == "https://example.test/api/"
    assert normalize_target("http://localhost:8000") == "http://localhost:8000/"
    with pytest.raises(ConfigurationError):
        normalize_target("http://example.test")


@pytest.mark.parametrize("endpoint", ["users", "//evil.test/path", "/x?q=1"])
def test_normalize_endpoint_rejects_ambiguous_values(endpoint: str) -> None:
    with pytest.raises(ConfigurationError):
        normalize_endpoint(endpoint)


def test_scanner_reports_accepted_candidate_without_disclosing_secret() -> None:
    session = FakeSession([401, 200])
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    report = scanner.scan(
        targets=["https://example.test"],
        endpoints=["/api/me"],
        secrets=["weak-secret"],
    )

    assert report.requests_sent == 2
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.baseline_status == 401
    assert finding.authenticated_status == 200
    assert finding.secret_fingerprint.startswith("sha256:")
    assert "weak-secret" not in str(report.as_dict())
    assert session.calls[0][1]["allow_redirects"] is False


def test_scanner_skips_public_endpoint() -> None:
    session = FakeSession([200])
    scanner = Scanner(session=session, delay=0, sleeper=lambda _: None)  # type: ignore[arg-type]
    report = scanner.scan(
        targets=["https://example.test"],
        endpoints=["/health"],
        secrets=["candidate"],
    )
    assert not report.findings
    assert report.requests_sent == 1
