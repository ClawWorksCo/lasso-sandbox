# Versioning Policy

LASSO follows [Semantic Versioning 2.0.0](https://semver.org/) (SemVer).

Given a version number **MAJOR.MINOR.PATCH**:

- **MAJOR** -- incremented for incompatible changes to the public API surface.
- **MINOR** -- incremented for new functionality that is backward-compatible.
- **PATCH** -- incremented for backward-compatible bug fixes.

## Public API Surface

The following are considered part of LASSO's public API. Changes to these require version bumps according to SemVer:

- **CLI flags and arguments** -- the `lasso` command-line interface, including all subcommands, flags, and their documented behavior.
- **TOML profile schema fields** -- the structure and field names in sandbox profile configuration files (`.lasso.toml`).

## Internal (Not Public API)

The following are considered internal implementation details and may change without notice in any release:

- Anything inside `lasso/core/` that is not exposed through the CLI.
- Dashboard HTML templates and static assets.
- Test utilities and fixtures.
- Internal helper functions and private methods (prefixed with `_`).
- Log message formats.

## Deprecation Policy

Before removing or making breaking changes to any public API surface:

1. The feature must be marked as deprecated for a **minimum of 1 minor version**.
2. A deprecation warning must be emitted at runtime when the deprecated feature is used.
3. The deprecation must be documented in `CHANGELOG.md` with a migration path.
4. The actual removal happens in the next **major version** release.

Example timeline:
- v0.5.0 -- `--old-flag` deprecated, warning emitted, docs updated.
- v1.0.0 -- `--old-flag` removed.

## Breaking Changes

Breaking changes to the public API surface are only permitted in **major version** releases. This includes:

- Removing or renaming CLI flags or subcommands.
- Changing TOML profile field names or removing fields.

During the 0.x development phase, minor versions may include breaking changes, but these will always be clearly documented in `CHANGELOG.md`.
