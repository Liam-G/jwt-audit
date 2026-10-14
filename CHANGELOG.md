# Changelog

All notable changes are documented here. This project follows semantic versioning.

## 0.3.0 - 2026-10-15

### Added

- OpenAPI JSON/YAML path import, curated endpoint packs, and bounded `FUZZ` template expansion.
- Custom JSON/YAML/JSONL payload corpora, typed CLI claims, and base-token claim seeding.
- Explicit HTTP method, algorithm, header-layout, and unsigned-token controls.
- Global request-rate, request-count, runtime, endpoint, and candidate limits.
- Retry/backoff handling for connection failures, timeouts, `429`, and transient gateway failures.
- No-traffic dry-run plans and partial-result notes when a hard limit stops a scan.

### Changed

- Discovery now tries each configured method in order after `405 Method Not Allowed`.
- Reports count endpoints actually tested when a scan stops early.

## 0.2.0 - 2026-10-15

### Added

- Safe, standard, and deep active-scan profiles.
- 28 standard and 33 deep identity/privilege payload mutations.
- HS256, HS384, HS512, alternate header ordering, and `alg=none` candidates.
- Optional RSA/HMAC algorithm-confusion candidates using supplied public keys.
- Common endpoint and placeholder-secret dictionaries.
- GET discovery, POST-on-405 fallback, denial-body matching, same-origin redirect handling, and confirmation requests.
- Concurrent multi-target scanning with bounded workers and request delay.
- Offline token inspection and candidate-secret verification.
- Text, JSON, and SARIF 2.1.0 reports.
- Debian-family packaging, manual page, and autopkgtest metadata.

### Changed

- Findings identify wordlist source lines and secret fingerprints without storing working tokens or raw secrets.
- Active scan results require a repeatable unauthenticated denial baseline.

## 0.1.0 - 2026-10-15

- Initial authorization-first weak-secret validator.
