from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jwt_audit import cli
from jwt_audit.models import ScanReport


def test_scan_requires_authorization_acknowledgement() -> None:
    assert cli.run(["scan", "--target", "https://example.test"]) == 1


class FakeScanner:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def scan(self, **kwargs: Any) -> ScanReport:
        return ScanReport.create(
            targets_scanned=1,
            endpoints_tested=38,
            protected_endpoints=0,
            requests_sent=38,
            findings=[],
            profile="standard",
        )


def test_standard_scan_uses_defaults(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(cli, "Scanner", FakeScanner)
    result = cli.run(
        [
            "scan",
            "--target",
            "https://example.test",
            "--format",
            "json",
            "--acknowledge-authorization",
            cli.AUTHORIZATION_ACK,
        ]
    )
    assert result == 0
    assert '"profile": "standard"' in capsys.readouterr().out


def test_header_parser() -> None:
    assert cli._parse_headers(["X-API-Key: value"]) == {"X-API-Key": "value"}
    try:
        cli._parse_headers(["invalid"])
    except cli.ConfigurationError:
        pass
    else:
        raise AssertionError("invalid header was accepted")


def test_claim_parser_handles_json_types_and_errors() -> None:
    assert cli._parse_claims(["admin=true", "sub=1", 'roles=["admin"]']) == {
        "admin": True,
        "sub": 1,
        "roles": ["admin"],
    }
    for invalid in ("missing-separator", "=true", "sub=not-json"):
        try:
            cli._parse_claims([invalid])
        except cli.ConfigurationError:
            pass
        else:
            raise AssertionError(f"invalid claim was accepted: {invalid}")


def test_dry_run_prints_fuzzed_bounded_plan(capsys: Any) -> None:
    result = cli.run(
        [
            "scan",
            "--target",
            "https://example.test",
            "--profile",
            "safe",
            "--secret-file",
            "/dev/null",
            "--common-secrets",
            "--no-builtin-endpoints",
            "--fuzz-template",
            "/api/FUZZ",
            "--max-endpoints",
            "20",
            "--dry-run",
            "--format",
            "json",
            "--acknowledge-authorization",
            cli.AUTHORIZATION_ACK,
        ]
    )
    assert result == 0
    output = capsys.readouterr().out
    assert '"dry_run": true' in output
    assert '"endpoints_per_target": 11' in output


def test_dry_run_supports_keyless_attack_families(capsys: Any) -> None:
    result = cli.run(
        [
            "scan",
            "--target",
            "https://example.test",
            "--endpoint",
            "/me",
            "--profile",
            "safe",
            "--no-common-secrets",
            "--include-key-edge-cases",
            "--include-algorithm-mutations",
            "--dry-run",
            "--format",
            "json",
            "--acknowledge-authorization",
            cli.AUTHORIZATION_ACK,
        ]
    )
    assert result == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["candidate_tokens_uncapped"] == 22


def test_inspect_command_reads_token_file(tmp_path: Path, capsys: Any) -> None:
    from jwt_audit.tokens import encode_unsigned

    token_file = tmp_path / "token.txt"
    token_file.write_text(encode_unsigned({"sub": "test"}), encoding="utf-8")
    assert cli.run(["inspect", "--token-file", str(token_file), "--format", "json"]) == 2
    assert '"JWT001"' in capsys.readouterr().out
