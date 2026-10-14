"""Offline JWT inspection and candidate-secret verification."""

from __future__ import annotations

import time
import warnings
from typing import Any

import jwt

from .tokens import SecretCandidate

SENSITIVE_CLAIMS = {"password", "passwd", "secret", "api_key", "apikey", "ssn", "credit_card"}


def _issue(identifier: str, title: str, severity: str, detail: str) -> dict[str, str]:
    return {"id": identifier, "title": title, "severity": severity, "detail": detail}


def inspect_token(token: str, secrets: tuple[SecretCandidate, ...] = ()) -> dict[str, Any]:
    """Inspect a compact JWT without contacting a remote system."""
    token = token.strip()
    if token.count(".") != 2:
        raise ValueError("input is not a three-part compact JWT")
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise ValueError(f"invalid JWT: {exc}") from exc
    issues: list[dict[str, str]] = []
    algorithm = str(header.get("alg", ""))
    if algorithm.lower() == "none":
        issues.append(_issue("JWT001", "Unsigned JWT", "critical", "The header selects alg=none."))
    if "exp" not in payload:
        issues.append(
            _issue("JWT002", "Missing expiration", "medium", "The token has no exp claim.")
        )
    elif isinstance(payload["exp"], (int, float)):
        lifetime_start = payload.get("iat", int(time.time()))
        if isinstance(lifetime_start, (int, float)) and payload["exp"] - lifetime_start > 86400:
            issues.append(
                _issue(
                    "JWT003", "Long token lifetime", "medium", "Token lifetime exceeds 24 hours."
                )
            )
    if "iss" not in payload:
        issues.append(_issue("JWT004", "Missing issuer", "low", "No iss claim is present."))
    if "aud" not in payload:
        issues.append(_issue("JWT005", "Missing audience", "low", "No aud claim is present."))
    remote_key_headers = sorted({"jku", "x5u"}.intersection(header))
    if remote_key_headers:
        issues.append(
            _issue(
                "JWT008",
                "Remote key reference",
                "high",
                f"Header references remote key material via: {', '.join(remote_key_headers)}.",
            )
        )
    if "jwk" in header:
        issues.append(
            _issue(
                "JWT009",
                "Embedded verification key",
                "high",
                "The header embeds a JWK; verifiers must not trust attacker-supplied keys.",
            )
        )
    key_id = header.get("kid")
    if isinstance(key_id, str) and any(marker in key_id for marker in ("../", "..\\", "'", '"')):
        issues.append(
            _issue(
                "JWT010",
                "Suspicious key identifier",
                "high",
                "The kid header contains path traversal or quoting characters.",
            )
        )
    exposed = sorted(SENSITIVE_CLAIMS.intersection(str(key).lower() for key in payload))
    if exposed:
        issues.append(
            _issue(
                "JWT006",
                "Sensitive claim names",
                "high",
                f"Potentially sensitive claims are present: {', '.join(exposed)}.",
            )
        )
    matched: dict[str, str] | None = None
    if algorithm in {"HS256", "HS384", "HS512"}:
        for secret in secrets:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    jwt.decode(
                        token,
                        secret.value,
                        algorithms=[algorithm],
                        options={"verify_exp": False, "verify_aud": False},
                    )
            except jwt.PyJWTError:
                continue
            matched = {"label": secret.label}
            issues.append(
                _issue(
                    "JWT007",
                    "Candidate HMAC secret matched",
                    "critical",
                    f"The signature verifies with {secret.label}.",
                )
            )
            break
    return {
        "schema_version": "1.0",
        "header": header,
        "payload": payload,
        "matched_candidate": matched,
        "issues": issues,
        "summary": {
            "algorithm": algorithm,
            "issues": len(issues),
            "highest_severity": next(
                (
                    severity
                    for severity in ("critical", "high", "medium", "low")
                    if any(issue["severity"] == severity for issue in issues)
                ),
                "none",
            ),
        },
    }
