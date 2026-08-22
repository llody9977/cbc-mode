# Contributing

Thanks for your interest in cbc-mode.

## Reporting issues

- **Bugs and features**: open an issue using the templates under **New issue**.
- **Security vulnerabilities**: do **not** open a public issue — follow [`SECURITY.md`](SECURITY.md) to report privately.

## Proposing changes

0. Install the local hooks once: `pipx install pre-commit && pre-commit install && pre-commit install --hook-type pre-push`. They block a commit or push that contains a secret.
1. Fork and branch from `main` (`feature/short-description` or `fix/short-description`).
2. Keep the change focused; one logical change per pull request.
3. Add or update tests, and make sure the existing suite and linters pass locally (`npm test` and `npm run lint`).
4. Run the project's pre-check-in review before opening the PR.
5. Open a pull request against `main` and fill in the PR template.

## Commit and PR conventions

- Write clear, imperative commit subjects ("Add X", "Fix Y"), with a body explaining *why* when it is not obvious.
- Do not add AI attribution trailers (`Co-Authored-By: Claude` or similar).
- Keep pull requests small enough to review in one sitting.
- CI and code scanning must pass before merge; the default branch is protected.
