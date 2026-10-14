from __future__ import annotations

import jwt

from jwt_audit.tokens import default_payloads, encode_candidate


def test_default_payloads_are_short_lived() -> None:
    payloads = default_payloads(now=1_000)
    assert len(payloads) == 2
    assert all(payload["iat"] == 1_000 for payload in payloads)
    assert all(payload["exp"] == 1_300 for payload in payloads)


def test_candidate_token_is_hs256() -> None:
    token = encode_candidate({"sub": "test"}, "candidate")
    assert jwt.get_unverified_header(token)["alg"] == "HS256"
    assert jwt.decode(token, "candidate", algorithms=["HS256"])["sub"] == "test"
