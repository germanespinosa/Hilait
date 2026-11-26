# Working on Hilait

Read [docs/CODEBASE.md](docs/CODEBASE.md) first: it maps the architecture,
stored files, APIs, and the security invariants (section 14) that changes
must preserve.

Workflow for every change:

1. `git pull` before starting so work begins from the latest `main`.
2. Make the change; add or update tests under `tests/`.
3. Run `python -m pytest -q` (install with `python -m pip install -e '.[test]'`).
   Rebuild the terminal bundle with `npm ci && npm run build` only if
   `src/hilait/static/terminal-entry.js` or xterm dependencies changed.
4. For user-visible changes, bump the version in both `pyproject.toml` and
   `src/hilait/__init__.py` (static assets are cache-busted by version), and add
   the version with its user-facing fixes at the top of `releases.json` (shown in
   Settings → Updates).
5. Update `README.md` for user-facing behaviour and `docs/CODEBASE.md` for
   architecture, API, storage, or invariant changes.
6. Commit with a short imperative subject (matching the existing history)
   and push to `main` on GitHub so the repository stays current. Tag the commit
   `v<version>` and push the tag: the in-app updater installs releases by tag.
