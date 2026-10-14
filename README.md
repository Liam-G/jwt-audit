# jwt-audit

`jwt-audit` is an authorization-first JWT security auditor for penetration testers, application-security teams, and CI pipelines. It combines active endpoint testing with offline token inspection and produces reproducible text, JSON, or SARIF evidence.

> [!CAUTION]
> Use active scanning only on systems you own or have explicit written permission to test. The acknowledgement flag records operator intent; it does not grant authorization.

## Capabilities

- discovers common protected administration, account, profile, and API endpoints;
- imports endpoint paths from OpenAPI JSON/YAML, curated endpoint packs, explicit lists, and safe `FUZZ` templates;
- restores the original 28 identity and privilege payload mutations and expands to 33 in deep mode;
- tests HS256, HS384, HS512, both common JWT header orderings, and optionally `alg=none`;
- tests RSA/HMAC algorithm confusion when an approved public key or certificate is supplied;
- checks built-in placeholder secrets plus operator-provided wordlists;
- detects real `401`/`403` responses, login redirects, and configurable denial text returned inside `200` responses;
- retries POST when endpoint discovery receives `405 Method Not Allowed`;
- follows candidate redirects only when they remain on the same origin;
- confirms every apparent acceptance with a fresh unauthenticated request;
- accepts custom JSON/YAML/JSONL claim corpora, individual typed claims, and a base token's unverified claims;
- controls HTTP methods, HMAC algorithms, header layouts, and unsigned-token testing from the CLI;
- scans multiple targets concurrently with bounded workers, delay, global rate limiting, retry/backoff, and hard request/runtime caps;
- caps endpoints and generated candidates, reports truncation, and provides a no-traffic dry run;
- identifies the matching wordlist line without writing raw secrets or working bearer tokens to reports;
- inspects JWTs offline for unsigned algorithms, matching HMAC secrets, missing `exp`/`iss`/`aud`, long lifetimes, and sensitive claim names;
- emits human-readable text, machine-readable JSON, and SARIF 2.1.0.

## Profiles

| Profile | Endpoints | Payloads | Algorithms | Header variants | Unsigned JWT |
|---|---:|---:|---|---:|---:|
| `safe` | Explicit only | 2 | HS256 | Library default | No |
| `standard` | 42 built in + explicit | 28 | HS256 | `alg` first, `typ` first | No |
| `deep` | 55 built in + explicit | 33 | HS256/384/512 | `alg` first, `typ` first | Yes |

The scanner stops after confirming one finding per vulnerability class—weak secret, unsigned token, and algorithm confusion—on each endpoint. This keeps deep scans bounded while testing every candidate until each configured class is proven.

## Installation

Python 3.10 or newer:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Development installation:

```bash
python -m pip install -e '.[dev]'
```

JSON inputs work with the base installation. YAML OpenAPI and payload files require
`PyYAML` (`python -m pip install PyYAML`); Debian-family packages install it automatically.

## Active scanning

The standard profile is the normal starting point. It includes the built-in endpoint and placeholder-secret dictionaries:

```bash
jwt-audit scan \
  --target https://staging.example.test \
  --profile standard \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Add a wordlist, custom endpoints, and JSON output:

```bash
jwt-audit scan \
  --target https://staging.example.test/api \
  --endpoint /v2/session \
  --endpoint /v2/admin/users \
  --secret-file candidates.txt \
  --profile standard \
  --format json \
  --output report.json \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Deep testing with SARIF output:

```bash
jwt-audit scan \
  --target-file authorized-targets.txt \
  --endpoint-file application-routes.txt \
  --secret-file candidates.txt \
  --profile deep \
  --workers 8 \
  --delay 0.2 \
  --format sarif \
  --output jwt-audit.sarif \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Import an OpenAPI description and expand application-specific endpoint words:

```bash
jwt-audit scan \
  --target https://staging.example.test \
  --openapi openapi.yaml \
  --endpoint-pack admin --endpoint-pack account \
  --fuzz-template '/api/v2/FUZZ' \
  --fuzz-wordlist routes.txt \
  --fuzz-extension json \
  --secret-file candidates.txt \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Use an application-specific claims corpus and explicit scan budgets:

```bash
jwt-audit scan \
  --target https://staging.example.test \
  --payload-file claims.jsonl \
  --claim 'tenant_id=1' \
  --method GET --method POST \
  --algorithm HS256 --algorithm HS512 \
  --rate 4 --retries 2 --backoff 0.5 \
  --max-requests 5000 --max-runtime 900 \
  --max-endpoints 300 --max-candidates 10000 \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Preview the exact counts and limits without sending traffic:

```bash
jwt-audit scan \
  --target https://staging.example.test \
  --profile deep --fuzz --dry-run --format json \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Test a known RSA public key as an HMAC secret (the classic RS256-to-HS256 confusion condition):

```bash
jwt-audit scan \
  --target https://staging.example.test \
  --profile deep \
  --confusion-key public-key.pem \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Use `--deny-pattern` for applications that return a custom denial message with status `200`. Use `--no-common-secrets` to test only your supplied wordlist. Plain HTTP is limited to loopback unless `--allow-insecure-http` is explicitly supplied.

For authenticated staging gateways and interception workflows, use repeated `--header NAME:VALUE`, `--proxy`, or `--token-cookie NAME`. TLS verification remains enabled unless `--no-verify-tls` is explicitly selected. Custom `Authorization` headers are rejected because that header is reserved for bearer candidates; use static cookies or another gateway header for surrounding authentication.

Exit status is `0` when no finding is confirmed, `2` when findings exist, and `1` for configuration or operational errors.

## Offline inspection

Reading tokens from a file or standard input avoids putting bearer tokens in shell history:

```bash
jwt-audit inspect --token-file token.txt --common-secrets
printf '%s' "$JWT_TO_INSPECT" | jwt-audit inspect --format json
```

Offline inspection performs no network requests.

## How active confirmation works

1. Request each endpoint without a token.
2. Treat `401`, `403`, login redirects, and configured denial bodies as protected.
3. On `405`, try the next configured method (GET then POST by default).
4. Generate candidates from the selected profile's payloads, algorithms, header layouts, and secrets.
5. Treat a non-denial `2xx` as possible acceptance; same-origin candidate redirects may be followed up to three hops.
6. Repeat the original request without a token. Report only if that confirmation is still denied.

This removes the original scanner's most common false positives: public `200` pages, redirects to login screens, redirects to unrelated origins, and applications that encode denial messages inside successful HTTP responses.

## Reports and secret handling

Reports never contain raw candidate secrets or generated bearer tokens. A successful wordlist candidate is identified by source and line, such as `candidates.txt:12`, plus a truncated SHA-256 fingerprint. That is enough to reproduce a result locally without leaking the value into CI logs or uploaded SARIF.

Local input and output files such as `secrets.txt`, `*.report.json`, and `reports/` are ignored by Git.

## Development

```bash
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```

Tests use in-memory HTTP fakes and never contact external targets. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Debian, Kali, and Parrot packaging

The repository includes Debian source-package metadata, a manual page, and an autopkgtest definition. Build in a clean Debian-family packaging environment:

```bash
sudo apt install build-essential devscripts debhelper dh-python \
  pybuild-plugin-pyproject python3-all python3-hatchling \
  python3-jwt python3-requests python3-yaml python3-pytest python3-pytest-cov

dpkg-buildpackage -us -uc -b
lintian ../jwt-audit_0.3.0-1_all.deb
```

For distribution submission, create and sign a tagged upstream release, generate `jwt-audit_0.3.0.orig.tar.gz`, build with `sbuild`, run `lintian` and `autopkgtest`, and maintain distribution-specific packaging branches. Kali and Parrot both follow Debian source-package workflows; their maintainers make the final repository and section decisions.

## Project

Created and maintained by [Liam Giannini](https://github.com/Liam-G) of [Webcracy.ch](https://webcracy.ch).

Licensed under the MIT License. Vulnerabilities in `jwt-audit` itself should be reported privately as described in [SECURITY.md](SECURITY.md).

