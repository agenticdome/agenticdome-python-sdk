# Contributing to the AgenticDome Python SDK

Thank you for evaluating or contributing to the public AgenticDome Python SDK source.

## Development environment

From the SDK root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

Dependency installation may require network access. Once dependencies are installed, the public test suite does not require AgenticDome credentials or connections to live AgenticDome or third-party services:

```bash
python -m pytest -q
```

## Build verification

Create the public wheel and source distribution, then validate their package metadata:

```bash
python -m build
python -m twine check dist/*
```

These commands validate public source artifacts only. Live runtime certification and package publication are operated separately by AgenticDome.

## Adding or updating a framework example

1. Add or update the dependency-light example under `examples/frameworks/`.
2. Demonstrate one allowed action and one blocked action without executing a real tool.
3. Register the framework in the public demo catalog when it is a new integration.
4. Add or update the corresponding adapter test under `tests/`.
5. Update the framework gallery and production integration playbook when the public attachment point changes.

Examples must use public SDK interfaces, placeholder credentials, and synthetic data. Do not publish private endpoints, tenant evidence, detection rules, internal policy logic, or release-runner implementation.

## Pull requests

- Keep changes focused and explain the user-visible security behavior.
- Add regression tests for changed behavior and update customer documentation where required.
- Run `python -m pytest -q`, `python -m build`, and `python -m twine check dist/*` before requesting review.
- Expect security-sensitive changes to require maintainer review and possible design changes before merge.
- By submitting a contribution, you agree that it is provided under the repository's Apache-2.0 license.

## Security and support

Do not include tenant credentials, customer data or private runtime evidence in issues or contributions. Use the public [issue tracker](https://github.com/agenticdome/agenticdome-python-sdk/issues) for reproducible SDK defects that contain no sensitive information.

Report suspected vulnerabilities privately to **info@agenticdome.io**. Do not open a public issue for a security vulnerability; follow [SECURITY.md](SECURITY.md).
