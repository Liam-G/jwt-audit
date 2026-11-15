"""Command-line interface for active scanning and offline JWT inspection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import jwt
import requests

from . import __version__
from .discovery import (
    DEFAULT_FUZZ_TEMPLATES,
    DEFAULT_FUZZ_WORDS,
    deduplicate_payloads,
    expand_fuzz_templates,
    load_openapi_paths,
    load_payloads,
)
from .inspector import inspect_token
from .profiles import ENDPOINT_PACKS, PROFILES
from .reporting import render_scan
from .scanner import ConfigurationError, Scanner, normalize_endpoint, normalize_target
from .tokens import (
    COMMON_SECRETS,
    SecretCandidate,
    build_payloads,
    candidate_count,
    default_payloads,
)

AUTHORIZATION_ACK = "I_HAVE_AUTHORIZATION"


def _add_secret_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--secret-file",
        type=Path,
        help="Newline-delimited candidate secrets; values are redacted from reports",
    )
    parser.add_argument(
        "--common-secrets",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Include the built-in placeholder-secret dictionary",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwt-audit",
        description="Authorization-first JWT implementation auditor.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Actively test explicitly authorized HTTP targets")
    scan.add_argument(
        "--target", action="append", default=[], help="Authorized base URL; repeatable"
    )
    scan.add_argument("--target-file", type=Path, help="Newline-delimited authorized targets")
    scan.add_argument("--endpoint", action="append", default=[], help="Additional path; repeatable")
    scan.add_argument("--endpoint-file", type=Path, help="Newline-delimited additional paths")
    scan.add_argument(
        "--endpoint-pack",
        action="append",
        choices=tuple(ENDPOINT_PACKS),
        default=[],
        help="Add a curated endpoint family; repeatable",
    )
    scan.add_argument(
        "--openapi",
        action="append",
        type=Path,
        default=[],
        help="Import paths from OpenAPI JSON/YAML",
    )
    scan.add_argument(
        "--fuzz", action="store_true", help="Enable built-in FUZZ templates and words"
    )
    scan.add_argument(
        "--fuzz-template", action="append", default=[], metavar="PATH", help="Path containing FUZZ"
    )
    scan.add_argument("--fuzz-wordlist", type=Path, help="Newline-delimited FUZZ replacements")
    scan.add_argument(
        "--fuzz-extension",
        action="append",
        default=[],
        metavar="EXT",
        help="Extension such as json",
    )
    scan.add_argument("--no-builtin-endpoints", action="store_true")
    scan.add_argument("--profile", choices=("safe", "standard", "deep"), default="standard")
    _add_secret_options(scan)
    scan.add_argument(
        "--confusion-key",
        type=Path,
        help="Public key/certificate to test as an HMAC secret for algorithm confusion",
    )
    scan.add_argument(
        "--workers", type=int, help="Parallel targets (1-32; profile default otherwise)"
    )
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--delay", type=float, default=0.25, help="Delay before each request")
    scan.add_argument("--rate", type=float, help="Global maximum requests per second")
    scan.add_argument("--retries", type=int, default=1, help="Retries for timeouts/429/5xx (0-10)")
    scan.add_argument("--backoff", type=float, default=0.5, help="Exponential retry backoff")
    scan.add_argument("--max-requests", type=int, default=10_000, help="Hard global request budget")
    scan.add_argument(
        "--max-runtime", type=float, default=600.0, help="Hard runtime budget in seconds"
    )
    scan.add_argument("--max-candidates", type=int, default=5_000)
    scan.add_argument("--max-endpoints", type=int, default=500)
    scan.add_argument(
        "--method",
        action="append",
        choices=("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"),
        default=[],
        help="Discovery/test method order; repeatable",
    )
    scan.add_argument(
        "--algorithm",
        action="append",
        choices=("HS256", "HS384", "HS512"),
        default=[],
    )
    scan.add_argument(
        "--header-variant",
        action="append",
        choices=("library", "alg-first", "typ-first"),
        default=[],
    )
    scan.add_argument("--include-unsigned", action=argparse.BooleanOptionalAction, default=None)
    scan.add_argument(
        "--include-key-edge-cases",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Test empty, null-byte, and literal-null HMAC keys",
    )
    scan.add_argument(
        "--include-algorithm-mutations",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Test case, missing/null/duplicate alg, and empty-signature variants",
    )
    scan.add_argument(
        "--payload-file",
        action="append",
        type=Path,
        default=[],
        help="JSON/YAML/JSONL claims corpus",
    )
    scan.add_argument(
        "--claim", action="append", default=[], metavar="NAME=JSON", help="Build one custom payload"
    )
    scan.add_argument(
        "--base-token-file", type=Path, help="Seed a payload from unverified JWT claims"
    )
    scan.add_argument("--no-builtin-payloads", action="store_true")
    scan.add_argument(
        "--deny-pattern", action="append", default=[], help="Extra denial-body marker"
    )
    scan.add_argument(
        "--header", action="append", default=[], metavar="NAME:VALUE", help="Static request header"
    )
    scan.add_argument("--proxy", help="HTTP(S) proxy URL, for example http://127.0.0.1:8080")
    scan.add_argument("--no-verify-tls", action="store_true", help="Disable TLS certificate checks")
    scan.add_argument(
        "--token-cookie", metavar="NAME", help="Send JWTs in this cookie instead of Authorization"
    )
    scan.add_argument("--allow-insecure-http", action="store_true")
    scan.add_argument("--quiet", action="store_true", help="Suppress progress messages")
    scan.add_argument(
        "--dry-run", action="store_true", help="Print the bounded scan plan; send no traffic"
    )
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output", type=Path, help="Write the report instead of stdout")
    scan.add_argument(
        "--acknowledge-authorization",
        metavar="PHRASE",
        help=f"Required acknowledgement phrase: {AUTHORIZATION_ACK}",
    )

    inspect = commands.add_parser("inspect", help="Inspect a JWT offline without network access")
    inspect.add_argument(
        "--token-file", type=Path, help="Read the token from a file (stdin otherwise)"
    )
    _add_secret_options(inspect)
    inspect.add_argument("--format", choices=("text", "json"), default="text")
    inspect.add_argument("--output", type=Path)
    return parser


def _load_lines(path: Path | None) -> list[tuple[str, int]]:
    if path is None:
        return []
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ConfigurationError(f"input file is larger than 10 MiB: {path}")
    result: list[tuple[str, int]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        value = line.strip()
        if value and not value.startswith("#"):
            result.append((value, number))
    return result


def _load_secrets(path: Path | None, *, include_common: bool) -> tuple[SecretCandidate, ...]:
    source_name = path.name if path is not None else "secrets"
    candidates = [
        SecretCandidate(value, f"{source_name}:{number}") for value, number in _load_lines(path)
    ]
    if include_common:
        candidates.extend(
            SecretCandidate(value, f"builtin:{number}")
            for number, value in enumerate(COMMON_SECRETS, start=1)
        )
    unique: dict[str, SecretCandidate] = {}
    for candidate in candidates:
        unique.setdefault(candidate.value, candidate)
    return tuple(unique.values())


def _parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        if ":" not in value:
            raise ConfigurationError(f"header must use NAME:VALUE syntax: {value!r}")
        name, content = value.split(":", 1)
        name = name.strip()
        if not name:
            raise ConfigurationError("header name cannot be empty")
        headers[name] = content.strip()
    return headers


def _parse_claims(values: list[str]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for value in values:
        if "=" not in value:
            raise ConfigurationError(f"claim must use NAME=JSON syntax: {value!r}")
        name, raw = value.split("=", 1)
        if not name.strip():
            raise ConfigurationError("claim name cannot be empty")
        try:
            payload[name.strip()] = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"invalid JSON claim value for {name!r}: {exc}") from exc
    return payload


def _scan_plan(
    args: argparse.Namespace,
    targets: list[str],
    endpoints: list[str],
    secrets: tuple[SecretCandidate, ...],
    payloads: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    selected = PROFILES[args.profile]
    clean_targets = tuple(
        dict.fromkeys(
            normalize_target(target, allow_insecure_http=args.allow_insecure_http)
            for target in targets
        )
    )
    builtins = () if args.no_builtin_endpoints else selected.endpoints
    clean_endpoints = tuple(
        dict.fromkeys(normalize_endpoint(endpoint) for endpoint in (*endpoints, *builtins))
    )
    if not clean_targets:
        raise ConfigurationError("at least one target is required")
    if not clean_endpoints:
        raise ConfigurationError("at least one endpoint is required")
    if len(clean_endpoints) > args.max_endpoints:
        raise ConfigurationError(
            f"endpoint count {len(clean_endpoints)} exceeds --max-endpoints {args.max_endpoints}"
        )
    algorithms = tuple(dict.fromkeys(args.algorithm)) or selected.algorithms
    variants = tuple(dict.fromkeys(args.header_variant)) or selected.header_variants
    unsigned = selected.include_unsigned if args.include_unsigned is None else args.include_unsigned
    key_edges = (
        selected.include_key_edge_cases
        if args.include_key_edge_cases is None
        else args.include_key_edge_cases
    )
    algorithm_mutations = (
        selected.include_algorithm_mutations
        if args.include_algorithm_mutations is None
        else args.include_algorithm_mutations
    )
    base_count = 0
    if not args.no_builtin_payloads:
        base_count = (
            len(default_payloads())
            if args.profile == "safe"
            else len(build_payloads("target", deep=selected.deep_payloads))
        )
    payload_count = base_count + len(payloads)
    if payload_count == 0:
        raise ConfigurationError("at least one payload is required")
    if not secrets and not (unsigned or key_edges or algorithm_mutations):
        raise ConfigurationError("at least one candidate secret or keyless attack is required")
    candidates = candidate_count(
        payload_count,
        len(secrets),
        algorithms=algorithms,
        header_variants=variants,
        include_unsigned=unsigned,
        include_key_edge_cases=key_edges,
        include_algorithm_mutations=algorithm_mutations,
    )
    return {
        "dry_run": True,
        "profile": args.profile,
        "targets": len(clean_targets),
        "endpoints_per_target": len(clean_endpoints),
        "methods": args.method or list(selected.methods),
        "payloads_per_target": payload_count,
        "candidate_tokens_per_target": min(candidates, args.max_candidates),
        "candidate_tokens_uncapped": candidates,
        "limits": {
            "max_endpoints": args.max_endpoints,
            "max_candidates": args.max_candidates,
            "max_requests": args.max_requests,
            "max_runtime_seconds": args.max_runtime,
            "rate_per_second": args.rate,
            "workers": args.workers or selected.workers,
        },
    }


def _render_plan(plan: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(plan, indent=2) + "\n"
    if output_format == "sarif":
        raise ConfigurationError("SARIF is only available for completed scans")
    return (
        "\n".join(
            (
                "jwt-audit dry-run plan (no traffic sent)",
                f"profile: {plan['profile']}",
                f"targets: {plan['targets']}",
                f"endpoints per target: {plan['endpoints_per_target']}",
                f"methods: {', '.join(plan['methods'])}",
                f"payloads per target: {plan['payloads_per_target']}",
                f"candidate tokens per target: {plan['candidate_tokens_per_target']} "
                f"(uncapped: {plan['candidate_tokens_uncapped']})",
                f"hard request budget: {plan['limits']['max_requests']}",
                f"hard runtime: {plan['limits']['max_runtime_seconds']}s",
            )
        )
        + "\n"
    )


def _write(rendered: str, output: Path | None) -> int:
    if output is None:
        print(rendered, end="")
        return 0
    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1
    print(f"Report written to {output}")
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    if args.acknowledge_authorization != AUTHORIZATION_ACK:
        print(
            "error: only scan systems you own or are explicitly authorized to test; "
            f"pass --acknowledge-authorization {AUTHORIZATION_ACK}",
            file=sys.stderr,
        )
        return 1
    include_common = args.common_secrets
    if include_common is None:
        include_common = args.profile in {"standard", "deep"}
    try:
        targets = [*args.target, *(value for value, _ in _load_lines(args.target_file))]
        endpoints = [*args.endpoint, *(value for value, _ in _load_lines(args.endpoint_file))]
        for pack in args.endpoint_pack:
            endpoints.extend(ENDPOINT_PACKS[pack])
        for specification in args.openapi:
            endpoints.extend(load_openapi_paths(specification))
        templates = list(args.fuzz_template)
        if args.fuzz:
            templates.extend(DEFAULT_FUZZ_TEMPLATES)
        if templates or args.fuzz_wordlist is not None:
            words = (
                [value for value, _ in _load_lines(args.fuzz_wordlist)]
                if args.fuzz_wordlist is not None
                else list(DEFAULT_FUZZ_WORDS)
            )
            endpoints.extend(
                expand_fuzz_templates(
                    templates or DEFAULT_FUZZ_TEMPLATES,
                    words,
                    args.fuzz_extension or [""],
                    args.max_endpoints,
                )
            )
        secrets = _load_secrets(args.secret_file, include_common=include_common)
        if args.confusion_key is not None:
            confusion_value = args.confusion_key.read_text(encoding="utf-8")
            secrets = (
                *secrets,
                SecretCandidate(
                    confusion_value,
                    f"confusion-key:{args.confusion_key.name}",
                    "confusion-key",
                ),
            )
        custom_payloads: list[dict[str, Any]] = []
        for payload_file in args.payload_file:
            custom_payloads.extend(load_payloads(payload_file))
        base_payload: dict[str, Any] = {}
        if args.base_token_file is not None:
            token = args.base_token_file.read_text(encoding="utf-8").strip()
            decoded = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
            )
            if not isinstance(decoded, dict):
                raise ConfigurationError("base token payload is not an object")
            base_payload.update(decoded)
        base_payload.update(_parse_claims(args.claim))
        if base_payload:
            custom_payloads.append(base_payload)
        payloads = deduplicate_payloads(custom_payloads)
        if args.dry_run:
            return _write(
                _render_plan(_scan_plan(args, targets, endpoints, secrets, payloads), args.format),
                args.output,
            )
        scanner = Scanner(
            timeout=args.timeout,
            delay=args.delay,
            rate=args.rate,
            retries=args.retries,
            backoff=args.backoff,
            max_requests=args.max_requests,
            max_runtime=args.max_runtime,
            max_candidates=args.max_candidates,
            max_endpoints=args.max_endpoints,
            workers=args.workers,
            denial_patterns=args.deny_pattern,
            headers=_parse_headers(args.header),
            proxy=args.proxy,
            verify_tls=not args.no_verify_tls,
            token_cookie=args.token_cookie,
            progress=None
            if args.quiet
            else lambda message: print(f"[*] {message}", file=sys.stderr),
        )
        report = scanner.scan(
            targets=targets,
            endpoints=endpoints,
            secrets=secrets,
            profile=args.profile,
            allow_insecure_http=args.allow_insecure_http,
            methods=args.method,
            algorithms=args.algorithm,
            header_variants=args.header_variant,
            include_unsigned=args.include_unsigned,
            include_key_edge_cases=args.include_key_edge_cases,
            include_algorithm_mutations=args.include_algorithm_mutations,
            include_builtin_endpoints=not args.no_builtin_endpoints,
            payloads=payloads,
            include_builtin_payloads=not args.no_builtin_payloads,
        )
    except (
        ConfigurationError,
        OSError,
        ValueError,
        jwt.PyJWTError,
        requests.RequestException,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if _write(render_scan(report, args.format), args.output):
        return 1
    return 2 if report.findings else 0


def _render_inspection(result: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result, indent=2) + "\n"
    lines = [
        "jwt-audit offline inspection",
        f"algorithm: {result['summary']['algorithm']}",
        f"issues: {result['summary']['issues']}",
        f"highest severity: {result['summary']['highest_severity']}",
    ]
    for issue in result["issues"]:
        lines.extend(
            (
                "",
                f"[{issue['severity'].upper()}] {issue['id']} {issue['title']}",
                f"  {issue['detail']}",
            )
        )
    return "\n".join(lines) + "\n"


def _run_inspect(args: argparse.Namespace) -> int:
    try:
        token = (
            args.token_file.read_text(encoding="utf-8")
            if args.token_file is not None
            else sys.stdin.read()
        )
        include_common = bool(args.common_secrets)
        secrets = _load_secrets(args.secret_file, include_common=include_common)
        result = inspect_token(token, secrets)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if _write(_render_inspection(result, args.format), args.output):
        return 1
    return 2 if result["issues"] else 0


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _run_scan(args) if args.command == "scan" else _run_inspect(args)


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
