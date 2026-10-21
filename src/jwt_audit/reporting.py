"""Text, JSON, and SARIF report renderers."""

from __future__ import annotations

import json
from typing import Any

from .models import ScanReport


def render_text(report: ScanReport) -> str:
    lines = [
        "jwt-audit scan report",
        f"profile: {report.profile}",
        f"targets: {report.targets_scanned}",
        f"endpoints tested: {report.endpoints_tested}",
        f"protected endpoints: {report.protected_endpoints}",
        f"requests: {report.requests_sent}",
        f"findings: {len(report.findings)}",
    ]
    for finding in report.findings:
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.title}",
                f"  target: {finding.target}{finding.endpoint}",
                f"  method: {finding.method}",
                f"  algorithm/header: {finding.algorithm}/{finding.header_variant}",
                f"  baseline -> candidate: {finding.baseline_status} -> "
                f"{finding.authenticated_status}",
                f"  candidate: {finding.candidate_label}",
                f"  fingerprint: {finding.secret_fingerprint or 'n/a'}",
                f"  payload: {json.dumps(finding.payload, sort_keys=True)}",
            ]
        )
    if report.errors:
        lines.extend(("", f"errors: {len(report.errors)}"))
        lines.extend(f"  - {error}" for error in report.errors)
    if report.notes:
        lines.extend(("", f"notes: {len(report.notes)}"))
        lines.extend(f"  - {note}" for note in report.notes)
    return "\n".join(lines) + "\n"


def render_sarif(report: ScanReport) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rule_id = {
            "unsigned": "JWT-ALG-NONE",
            "algorithm-manipulation": "JWT-ALG-MANIPULATION",
            "algorithm-confusion": "JWT-ALG-CONFUSION",
            "key-edge-case": "JWT-EMPTY-NULL-KEY",
            "weak-hmac-key": "JWT-WEAK-SECRET",
        }.get(finding.vulnerability_class, "JWT-FORGED-TOKEN")
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {
                "text": (
                    "Require an explicit algorithm allowlist, strong signing keys, "
                    "and strict claim validation."
                )
            },
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": f"{finding.method} {finding.target}{finding.endpoint} accepted "
                    f"a forged {finding.algorithm} token ({finding.candidate_label})."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"{finding.target}{finding.endpoint}"}
                        }
                    }
                ],
                "properties": finding.as_dict(),
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "jwt-audit",
                        "informationUri": "https://github.com/Liam-G/jwt-audit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def render_scan(report: ScanReport, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "sarif":
        return render_sarif(report)
    return json.dumps(report.as_dict(), indent=2) + "\n"
