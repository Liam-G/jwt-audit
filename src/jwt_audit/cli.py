"""Command-line interface for jwt-audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

from .scanner import ConfigurationError, Scanner

AUTHORIZATION_ACK = "I_HAVE_AUTHORIZATION"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwt-audit",
        description="Detect acceptance of JWTs signed with explicitly supplied weak secrets.",
    )
    parser.add_argument("--target", action="append", required=True, help="Authorized base URL")
    parser.add_argument(
        "--endpoint",
        action="append",
        required=True,
        help="Protected path to test; repeat for multiple paths",
    )
    parser.add_argument(
        "--secret-file",
        required=True,
        type=Path,
        help="Newline-delimited candidate secrets (never included in reports)",
    )
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--allow-insecure-http", action="store_true")
    parser.add_argument(
        "--acknowledge-authorization",
        metavar="PHRASE",
        help=f"Required acknowledgement phrase: {AUTHORIZATION_ACK}",
    )
    return parser


def _load_secrets(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.acknowledge_authorization != AUTHORIZATION_ACK:
        print(
            "error: only scan systems you own or are explicitly authorized to test; "
            f"pass --acknowledge-authorization {AUTHORIZATION_ACK}",
            file=sys.stderr,
        )
        return 1

    try:
        scanner = Scanner(timeout=args.timeout, delay=args.delay)
        report = scanner.scan(
            targets=args.target,
            endpoints=args.endpoint,
            secrets=_load_secrets(args.secret_file),
            allow_insecure_http=args.allow_insecure_http,
        )
    except (ConfigurationError, OSError, requests.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(report.as_dict(), indent=2)
    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 1
        print(f"Report written to {args.output}")
    else:
        print(rendered)
    return 2 if report.findings else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
