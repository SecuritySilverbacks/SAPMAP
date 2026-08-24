# Contributing to SAPMAP

Thank you for your interest in contributing to SAPMAP. This project is part of the [OWASP Core Business Application Security (CBAS)](https://owasp.org/www-project-core-business-application-security/) ecosystem.

## Authorization requirement

SAPMAP implements real exploits against SAP systems. Any testing, debugging, or development that touches live SAP systems **must** be performed against systems you own or have explicit written authorization to test. See `DISCLAIMER.md`.

## Reporting security vulnerabilities

If you discover a vulnerability in SAPMAP itself (e.g. a way to compromise the operator's machine), please report it privately via GitHub Security Advisories rather than opening a public issue.

If you discover a new SAP vulnerability using SAPMAP, please disclose it responsibly to SAP SE via <https://support.sap.com/en/my-support/product-security-response.html> before public disclosure.

## How to contribute

1. **Fork the repository** and create a feature branch from `main`.
2. **Make your changes.** Follow the existing code style (no linting config, but keep it consistent with what's there).
3. **Add tests** for new functionality in the `tests/` directory.
4. **Run the test suite** to confirm nothing is broken: `pytest tests/`
5. **Submit a pull request** with a clear description of what changed and why.

## What we welcome

- Bug fixes and robustness improvements
- New exploit modules or detection techniques (with responsible disclosure of any new vulnerabilities)
- Documentation improvements and examples
- Detection signatures and defensive tooling
- Test coverage

## Conventions

- No build step, no linting config, no pre-commit hooks.
- Lazy imports for optional dependencies (`pyrfc`, `pywebview`, `pycryptodome`, etc.).
- Multi-method fallback chains: when a primary method fails, silently try the next.
- Test fixtures must use generic placeholder data, never real credentials or infrastructure details.
- `.sapmap` state files are plain JSON.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see `LICENSE`).
