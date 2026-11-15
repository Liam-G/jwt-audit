from __future__ import annotations

from pathlib import Path

import pytest

from jwt_audit.discovery import (
    deduplicate_payloads,
    expand_fuzz_templates,
    load_openapi_paths,
    load_payloads,
)
from jwt_audit.scanner import ConfigurationError


def test_expand_fuzz_templates_with_extensions() -> None:
    assert expand_fuzz_templates(["/api/FUZZ"], ["admin", "me"], ["", "json"]) == (
        "/api/admin",
        "/api/admin.json",
        "/api/me",
        "/api/me.json",
    )
    with pytest.raises(ConfigurationError):
        expand_fuzz_templates(["/FUZZ"], ["https://outside.test/x"])


def test_load_openapi_json_and_replace_path_parameters(tmp_path: Path) -> None:
    specification = tmp_path / "openapi.json"
    specification.write_text(
        '{"openapi":"3.1.0","paths":{"/users/{id}":{},"/admin":{}}}',
        encoding="utf-8",
    )
    assert load_openapi_paths(specification) == ("/users/1", "/admin")


def test_load_yaml_payload_corpus(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    corpus = tmp_path / "payloads.yaml"
    corpus.write_text("- sub: admin\n  role: admin\n- sub: 1\n", encoding="utf-8")
    assert load_payloads(corpus) == (
        {"sub": "admin", "role": "admin"},
        {"sub": 1},
    )


def test_load_json_and_json_lines_payload_corpora(tmp_path: Path) -> None:
    corpus = tmp_path / "payloads.json"
    corpus.write_text('[{"sub":"admin"},{"sub":1}]', encoding="utf-8")
    assert load_payloads(corpus) == ({"sub": "admin"}, {"sub": 1})

    lines = tmp_path / "payloads.jsonl"
    lines.write_text('{"role":"admin"}\n# comment\n{"admin":true}\n', encoding="utf-8")
    assert load_payloads(lines) == ({"role": "admin"}, {"admin": True})


def test_discovery_inputs_reject_invalid_shapes(tmp_path: Path) -> None:
    invalid_openapi = tmp_path / "openapi.json"
    invalid_openapi.write_text('{"openapi":"3.1.0"}', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="no paths"):
        load_openapi_paths(invalid_openapi)

    invalid_payloads = tmp_path / "payloads.json"
    invalid_payloads.write_text('["not-an-object"]', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="objects"):
        load_payloads(invalid_payloads)

    with pytest.raises(ConfigurationError, match="extension"):
        expand_fuzz_templates(["/FUZZ"], ["admin"], ["../json"])


def test_payload_deduplication_and_json_validation() -> None:
    assert deduplicate_payloads([{"sub": 1}, {"sub": 1}, {"sub": 2}]) == (
        {"sub": 1},
        {"sub": 2},
    )
    with pytest.raises(ConfigurationError, match="valid JSON"):
        deduplicate_payloads([{"bad": {1, 2}}])
