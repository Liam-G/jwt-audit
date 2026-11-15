"""Serializable scan and inspection models."""

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
    algorithm: str
    header_variant: str
    payload: dict[str, Any]
    candidate_label: str | None = None
    secret_fingerprint: str | None = None
    redirected_to: str | None = None
    confidence: str = "high"
    title: str = "Forged JWT candidate was accepted"
    severity: str = "high"
    vulnerability_class: str = "weak-hmac-key"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    targets_scanned: int
    endpoints_tested: int
    protected_endpoints: int
    requests_sent: int
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    notes: tuple[str, ...]
    profile: str
    generated_at: str

    @classmethod
    def create(
        cls,
        *,
        targets_scanned: int,
        requests_sent: int,
        findings: list[Finding],
        endpoints_tested: int = 0,
        protected_endpoints: int = 0,
        errors: list[str] | None = None,
        notes: list[str] | None = None,
        profile: str = "safe",
    ) -> ScanReport:
        return cls(
            targets_scanned=targets_scanned,
            endpoints_tested=endpoints_tested,
            protected_endpoints=protected_endpoints,
            requests_sent=requests_sent,
            findings=tuple(findings),
            errors=tuple(errors or ()),
            notes=tuple(notes or ()),
            profile=profile,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "generated_at": self.generated_at,
            "profile": self.profile,
            "summary": {
                "targets_scanned": self.targets_scanned,
                "endpoints_tested": self.endpoints_tested,
                "protected_endpoints": self.protected_endpoints,
                "requests_sent": self.requests_sent,
                "findings": len(self.findings),
                "errors": len(self.errors),
                "notes": len(self.notes),
            },
            "findings": [finding.as_dict() for finding in self.findings],
            "errors": list(self.errors),
            "notes": list(self.notes),
        }
