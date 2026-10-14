# Contributing

Thank you for helping improve `jwt-audit`.

## Ground rules

- Test only systems you own or are explicitly authorized to assess.
- Do not commit scan output, live targets, credentials, bearer tokens, personal data, or secrets.
- Keep features bounded, observable, and useful for defensive validation. Changes intended for evasion, stealth, indiscriminate discovery, or unauthorized access will not be accepted.
- Open an issue before making a large behavioral change.

## Local workflow

1. Create a virtual environment and install `python -m pip install -e '.[dev]'`.
2. Add focused tests that do not require internet access.
3. Run `ruff check .`, `ruff format --check .`, `mypy src`, and `pytest`.
4. Update the README when behavior or CLI flags change.

Use short, imperative commit subjects. Pull requests should explain the security use case, safety implications, test coverage, and any compatibility impact.

