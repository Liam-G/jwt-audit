"""Generate narrowly scoped test tokens."""

from __future__ import annotations

import time
from typing import Any

import jwt


def default_payloads(now: int | None = None) -> tuple[dict[str, Any], ...]:
    """Return a small, deterministic set of claims for weak-secret validation."""
    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + 300
    return (
        {"sub": "jwt-audit", "iat": issued_at, "exp": expires_at},
        {
            "sub": "jwt-audit",
            "role": "admin",
            "iat": issued_at,
            "exp": expires_at,
        },
    )


def encode_candidate(payload: dict[str, Any], secret: str) -> str:
    """Create an HS256 token for an explicitly provided candidate secret."""
    return jwt.encode(payload, secret, algorithm="HS256", headers={"typ": "JWT"})
