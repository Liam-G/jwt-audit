from __future__ import annotations

import jwt

from jwt_audit.tokens import (
    SecretCandidate,
    build_payloads,
    default_payloads,
    encode_candidate,
    encode_unsigned,
    generate_candidates,
)


def test_payload_profiles_restore_and_extend_original_matrix() -> None:
    assert len(default_payloads(now=1_000)) == 2
    assert len(build_payloads("example.test", now=1_000)) == 28
    assert len(build_payloads("example.test", deep=True, now=1_000)) == 33


def test_hmac_algorithms_and_header_orderings_are_valid() -> None:
    for algorithm in ("HS256", "HS384", "HS512"):
        for variant in ("alg-first", "typ-first", "library"):
            token = encode_candidate(
                {"sub": "test"}, "candidate", algorithm=algorithm, header_variant=variant
            )
            assert jwt.get_unverified_header(token)["alg"] == algorithm
            assert jwt.decode(token, "candidate", algorithms=[algorithm])["sub"] == "test"


def test_unsigned_and_generated_candidates() -> None:
    unsigned = encode_unsigned({"sub": "admin"})
    assert jwt.get_unverified_header(unsigned)["alg"] == "none"
    candidates = generate_candidates(
        ({"sub": "admin"},),
        (SecretCandidate("secret", "test:1"),),
        algorithms=("HS256", "HS512"),
        header_variants=("alg-first", "typ-first"),
        include_unsigned=True,
    )
    assert len(candidates) == 5
