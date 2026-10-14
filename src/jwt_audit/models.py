"""Data models used by the scanner and report writer."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Finding:
    target: str
    endpoint: str
    method: str
    baseline_status: int
    authenticated_status: int
    secret_fingerprint: str
    payload: dict[str, Any]
    title: str = "JWT signed with a weak candidate secret was accepted"
    severity: str = "high"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    targets_scanned: int
    requests_sent: int
    findings: tuple[Finding, ...]
    generated_at: str

    @classmethod
    def create(
        cls, *, targets_scanned: int, requests_sent: int, findings: list[Finding]
    ) -> ScanReport:
        return cls(
            targets_scanned=targets_scanned,
            requests_sent=requests_sent,
            findings=tuple(findings),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "generated_at": self.generated_at,
            "summary": {
                "targets_scanned": self.targets_scanned,
                "requests_sent": self.requests_sent,
                "findings": len(self.findings),
            },
            "findings": [finding.as_dict() for finding in self.findings],
        }
