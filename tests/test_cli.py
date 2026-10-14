from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from jwt_audit import cli
from jwt_audit.models import ScanReport


def test_cli_requires_authorization_acknowledgement() -> None:
    arguments = [
        "--target",
        "https://example.test",
        "--endpoint",
        "/api/me",
        "--secret-file",
        "missing",
    ]
    assert cli.run(arguments) == 1


class FakeScanner:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def scan(self, **kwargs: Any) -> ScanReport:
        return ScanReport.create(targets_scanned=1, requests_sent=1, findings=[])


def authorized_arguments(secret_file: Path) -> list[str]:
    return [
        "--target",
        "https://example.test",
        "--endpoint",
        "/api/me",
        "--secret-file",
        str(secret_file),
        "--acknowledge-authorization",
        cli.AUTHORIZATION_ACK,
    ]


def test_cli_prints_json_report(monkeypatch: Any, tmp_path: Path, capsys: Any) -> None:
    secret_file = tmp_path / "candidates.txt"
    secret_file.write_text("# comment\n candidate \n", encoding="utf-8")
    monkeypatch.setattr(cli, "Scanner", FakeScanner)

    assert cli.run(authorized_arguments(secret_file)) == 0
    assert '"findings": 0' in capsys.readouterr().out


def test_cli_handles_scan_error(monkeypatch: Any, tmp_path: Path, capsys: Any) -> None:
    class FailingScanner(FakeScanner):
        def scan(self, **kwargs: Any) -> ScanReport:
            raise requests.RequestException("connection failed")

    secret_file = tmp_path / "candidates.txt"
    secret_file.write_text("candidate\n", encoding="utf-8")
    monkeypatch.setattr(cli, "Scanner", FailingScanner)

    assert cli.run(authorized_arguments(secret_file)) == 1
    assert "connection failed" in capsys.readouterr().err
