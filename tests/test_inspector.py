from __future__ import annotations

import jwt
import pytest

from jwt_audit.inspector import inspect_token
from jwt_audit.tokens import SecretCandidate, encode_unsigned


def test_inspector_finds_unsigned_missing_claims() -> None:
    result = inspect_token(encode_unsigned({"sub": "admin"}))
    identifiers = {issue["id"] for issue in result["issues"]}
    assert {"JWT001", "JWT002", "JWT004", "JWT005"}.issubset(identifiers)


def test_inspector_verifies_candidate_secret_without_returning_it() -> None:
    token = jwt.encode({"sub": "test", "exp": 9_999_999_999}, "weak", algorithm="HS256")
    result = inspect_token(token, (SecretCandidate("weak", "wordlist:2"),))
    assert result["matched_candidate"] == {"label": "wordlist:2"}
    assert "weak" not in str(result)


def test_inspector_rejects_non_jwt_and_flags_long_sensitive_payload() -> None:
    with pytest.raises(ValueError):
        inspect_token("not-a-jwt")
    with pytest.raises(ValueError):
        inspect_token("bad.bad.bad")
    token = jwt.encode(
        {"iat": 1, "exp": 90_000, "password": "example"},
        "strong-enough-for-test-only",
        algorithm="HS256",
    )
    identifiers = {issue["id"] for issue in inspect_token(token)["issues"]}
    assert {"JWT003", "JWT006"}.issubset(identifiers)


def test_inspector_flags_key_selection_headers() -> None:
    token = jwt.encode(
        {"sub": "test"},
        "strong-enough-for-test-only",
        algorithm="HS256",
        headers={"jku": "https://example.test/jwks", "jwk": {"kty": "oct"}, "kid": "../key"},
    )
    identifiers = {issue["id"] for issue in inspect_token(token)["issues"]}
    assert {"JWT008", "JWT009", "JWT010"}.issubset(identifiers)
