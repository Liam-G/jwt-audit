from __future__ import annotations

import json

from jwt_audit.models import Finding, ScanReport
from jwt_audit.reporting import render_sarif, render_scan, render_text


def sample_report() -> ScanReport:
    finding = Finding(
        target="https://example.test",
        endpoint="/admin",
        method="GET",
        baseline_status=401,
        authenticated_status=200,
        algorithm="HS256",
        header_variant="typ-first",
        payload={"sub": "admin"},
        candidate_label="wordlist:2",
        secret_fingerprint="sha256:123456789abc",  # noqa: S106
    )
    return ScanReport.create(
        targets_scanned=1,
        endpoints_tested=1,
        protected_endpoints=1,
        requests_sent=3,
        findings=[finding],
        errors=["one recoverable error"],
        profile="standard",
    )


def test_text_report_contains_evidence() -> None:
    report = sample_report()
    rendered = render_text(report)
    assert "401 -> 200" in rendered
    assert "wordlist:2" in rendered
    assert "one recoverable error" in rendered
    assert render_scan(report, "text") == rendered


def test_json_and_sarif_reports_are_valid() -> None:
    report = sample_report()
    assert json.loads(render_scan(report, "json"))["summary"]["findings"] == 1
    sarif = json.loads(render_sarif(report))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "JWT-WEAK-SECRET"
    assert json.loads(render_scan(report, "sarif"))["version"] == "2.1.0"
