# jwt-audit

`jwt-audit` is an authorization-first command-line tool for checking whether a protected HTTP endpoint accepts an HS256 JSON Web Token signed with a weak candidate secret.

The project is deliberately narrow: it establishes an unauthenticated `401`/`403` baseline, tries only secrets that the operator explicitly supplies, does not follow redirects, and redacts raw secrets and tokens from reports.

> [!CAUTION]
> Use this tool only on systems you own or have explicit written permission to test. A command-line acknowledgement is a guardrail, not a substitute for authorization. You are responsible for scope, rate limits, privacy, and applicable law.

## Why this project exists

JWT deployments sometimes ship with placeholder or leaked HMAC secrets. If an application accepts a token signed with such a secret, an attacker may be able to forge claims. `jwt-audit` gives defenders a reproducible way to validate that specific condition without bundling real-world targets or retaining bearer tokens.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For development:

```bash
python -m pip install -e '.[dev]'
```

## Usage

Create a local, untracked candidate file:

```text
# secrets.txt
known-placeholder-from-your-own-deployment
candidate-from-an-approved-wordlist
```

Scan explicitly approved endpoints:

```bash
jwt-audit \
  --target https://staging.example.test \
  --endpoint /api/me \
  --endpoint /api/admin \
  --secret-file secrets.txt \
  --delay 0.5 \
  --output staging.report.json \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Exit status is `0` when no issue is found, `2` when one or more findings are reported, and `1` for configuration or network errors. A finding is a validation signal, not proof of impact; reproduce it carefully and follow your disclosure process.

Plain HTTP is accepted on loopback for local labs. Other HTTP targets require `--allow-insecure-http` because bearer tokens can otherwise cross the network unencrypted.

## Detection model and limitations

For each target and endpoint, the scanner:

1. sends an unauthenticated `GET` without following redirects;
2. continues only if the response is `401` or `403`;
3. signs two short-lived test payloads with each supplied candidate secret;
4. reports a finding if a candidate receives a `2xx` response.

This conservative comparison reduces common redirect and public-page false positives, but it cannot determine whether returned data is sensitive or whether claims are authorized. It currently tests only HS256 bearer tokens and GET endpoints. It intentionally does not discover targets, crawl applications, bypass rate limits, randomize identities, or store working tokens.

## Safe local demo

Use an application you control. Point the scanner at a protected local endpoint that returns `401` without a token and `200` for a test token. A deliberately vulnerable example may be added later under `examples/`; the repository does not contact external systems during tests.

## Development

```bash
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Publishing checklist

Before creating the public repository:

1. initialize Git and confirm `git status --ignored` lists every legacy scan artifact as ignored;
2. run the checks above and inspect the contents of both files produced in `dist/`;
3. create `Liam-G/jwt-audit` on GitHub and enable private vulnerability reporting, Dependabot alerts, and branch protection;
4. create a signed `v0.1.0` tag only after CI passes.

The old scripts and collected `.txt` data in this working directory are intentionally ignored and explicitly excluded from package builds. Do not force-add them: they contain third-party targets and historical tokens/results. If any of those artifacts have ever entered Git history, rewrite the history before making the repository public and treat exposed credentials as compromised.

## Responsible-use design

- no built-in public targets or harvested data;
- explicit target, endpoint, secret file, and authorization acknowledgement;
- TLS required by default outside loopback;
- redirects disabled to avoid leaving scope;
- a visible user agent and a nonzero default delay;
- reports contain only a one-way secret fingerprint, never raw secrets or JWTs;
- tests use in-memory fakes and make no network requests.

## License

Created and maintained by [Liam Giannini](https://github.com/Liam-G) of [Webcracy.ch](https://webcracy.ch).

MIT. See [LICENSE](LICENSE).

