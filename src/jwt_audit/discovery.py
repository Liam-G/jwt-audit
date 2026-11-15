"""Endpoint and payload corpus loaders used by the active scanner."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from importlib import import_module
from pathlib import Path
from typing import Any

from .scanner import ConfigurationError, normalize_endpoint

DEFAULT_FUZZ_WORDS = (
    "admin",
    "account",
    "dashboard",
    "internal",
    "management",
    "me",
    "profile",
    "protected",
    "settings",
    "user",
    "users",
)

DEFAULT_FUZZ_TEMPLATES = (
    "/FUZZ",
    "/api/FUZZ",
    "/api/v1/FUZZ",
    "/v1/FUZZ",
)


def _load_structured(path: Path) -> Any:
    """Load a size-bounded JSON or YAML document."""
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ConfigurationError(f"input file is larger than 10 MiB: {path}")
    content = path.read_text(encoding="utf-8")
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            yaml = import_module("yaml")
        except ModuleNotFoundError as exc:
            raise ConfigurationError(
                f"{path} is not JSON and YAML support is unavailable; install PyYAML"
            ) from exc
        try:
            return yaml.safe_load(content)
        except Exception as exc:
            if exc.__class__.__module__.startswith("yaml"):
                raise ConfigurationError(f"invalid JSON/YAML in {path}: {exc}") from exc
            raise


def load_openapi_paths(path: Path) -> tuple[str, ...]:
    """Extract normalized paths from an OpenAPI 2/3 JSON or YAML document."""
    document = _load_structured(path)
    if not isinstance(document, Mapping) or not isinstance(document.get("paths"), Mapping):
        raise ConfigurationError(f"OpenAPI document has no paths object: {path}")
    paths: list[str] = []
    for raw_path in document["paths"]:
        if not isinstance(raw_path, str):
            raise ConfigurationError(f"OpenAPI path keys must be strings: {path}")
        # Path parameters cannot be guessed safely; use a stable harmless placeholder.
        endpoint = raw_path
        while "{" in endpoint and "}" in endpoint:
            start = endpoint.index("{")
            end = endpoint.index("}", start)
            endpoint = f"{endpoint[:start]}1{endpoint[end + 1 :]}"
        paths.append(normalize_endpoint(endpoint))
    return tuple(dict.fromkeys(paths))


def expand_fuzz_templates(
    templates: Iterable[str],
    words: Iterable[str],
    extensions: Iterable[str] = ("",),
    limit: int | None = None,
) -> tuple[str, ...]:
    """Expand FUZZ path templates without allowing URL/scope injection."""
    clean_words: list[str] = []
    for raw_word in words:
        word = raw_word.strip().strip("/")
        if not word or any(character in word for character in "?#\\") or "://" in word:
            raise ConfigurationError(f"unsafe fuzz word: {raw_word!r}")
        clean_words.append(word)
    clean_extensions: list[str] = []
    for raw_extension in extensions:
        extension = raw_extension.strip()
        if extension and not extension.startswith("."):
            extension = f".{extension}"
        if any(character in extension for character in "/?#\\"):
            raise ConfigurationError(f"unsafe fuzz extension: {raw_extension!r}")
        clean_extensions.append(extension)
    if not clean_extensions:
        clean_extensions.append("")

    expanded: list[str] = []
    seen: set[str] = set()
    for raw_template in templates:
        template = normalize_endpoint(raw_template.replace("FUZZ", "jwt-audit-placeholder"))
        template = template.replace("jwt-audit-placeholder", "FUZZ")
        for word in clean_words:
            for extension in clean_extensions:
                replacement = f"{word}{extension}"
                endpoint = (
                    template.replace("FUZZ", replacement)
                    if "FUZZ" in template
                    else f"{template.rstrip('/')}/{replacement}"
                )
                normalized = normalize_endpoint(endpoint)
                if normalized in seen:
                    continue
                seen.add(normalized)
                expanded.append(normalized)
                if limit is not None and len(expanded) > limit:
                    raise ConfigurationError(f"fuzz expansion exceeds --max-endpoints {limit}")
    return tuple(expanded)


def load_payloads(path: Path) -> tuple[dict[str, Any], ...]:
    """Load a JSON/YAML object, list of objects, or JSON Lines payload corpus."""
    try:
        document = _load_structured(path)
    except ConfigurationError:
        # YAML does not parse multi-document JSONL as a single value. Try it explicitly.
        payloads: list[dict[str, Any]] = []
        try:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ConfigurationError(f"payload at {path}:{number} is not an object")
                payloads.append(value)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"invalid payload corpus {path}: {exc}") from exc
        return tuple(payloads)

    values = document if isinstance(document, list) else [document]
    if not all(isinstance(value, dict) for value in values):
        raise ConfigurationError(f"payload corpus must contain JSON/YAML objects: {path}")
    return tuple(dict(value) for value in values)


def deduplicate_payloads(payloads: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Deduplicate JSON-compatible payloads while preserving order."""
    unique: dict[str, dict[str, Any]] = {}
    for payload in payloads:
        try:
            key = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"payload is not valid JSON: {exc}") from exc
        unique.setdefault(key, payload)
    return tuple(unique.values())
