# LASSO Dependencies

This document lists every direct dependency used by LASSO, explaining what it does,
why LASSO needs it, its license, and whether it is required or optional.

## Required Dependencies

These are installed automatically with `pip install lasso-sandbox`.

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **typer** | `>=0.9` | MIT | Powers the CLI interface (`lasso` command). Provides argument parsing, help generation, and subcommands with minimal boilerplate. |
| **rich** | `>=13.0` | MIT | Terminal output formatting: colored tables, panels, progress bars, and syntax highlighting used throughout the CLI. |
| **pydantic** | `>=2.0` | MIT | Data validation and schema enforcement for sandbox profiles, configuration models, and API request/response types. |
| **tomli** | `>=2.0` | MIT | TOML file parsing for reading sandbox profile configuration files. (Part of stdlib in Python 3.11+, but the package is needed for 3.10 support.) |
| **tomli_w** | `>=1.0` | MIT | TOML file writing for saving and exporting sandbox profiles. The stdlib `tomllib` is read-only, so this package handles serialization. |

## Optional Dependencies

Install these with extras: `pip install lasso-sandbox[extra_name]`.

### `dashboard` extra

```bash
pip install lasso-sandbox[dashboard]
```

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **flask** | `>=3.0` | BSD-3-Clause | Web framework for the LASSO dashboard UI. Provides routing, templating (Jinja2), and the application factory used by `lasso dashboard`. |

### `containers` extra

```bash
pip install lasso-sandbox[containers]
```

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **docker** | `>=7.0` | Apache-2.0 | Docker SDK for Python. Used by the Docker/Podman container backend to create, start, stop, inspect, and execute commands inside containers. Also compatible with Podman via the Docker-compatible socket. |

### `all` extra

Installs everything:

```bash
pip install lasso-sandbox[all]
```

This includes both `flask` and `docker`.

### `dev` extra

Development and testing tools (not needed for production use):

```bash
pip install lasso-sandbox[dev]
```

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **pytest** | `>=7.0` | MIT | Test runner for the LASSO test suite (813+ unit tests). |
| **pytest-cov** | any | MIT | Code coverage reporting plugin for pytest. |

## Graceful Degradation

LASSO is designed so that the core CLI works without optional dependencies:

- **Without `flask`**: The `lasso dashboard` command prints a helpful error message
  directing the user to install the `dashboard` extra. All other CLI commands work normally.
- **Without `docker`**: LASSO operates in native subprocess mode (Linux namespace
  isolation). The Docker/Podman container backend raises an `ImportError` with
  install instructions only when you attempt to use it.

## Build System

| Package | Version | Purpose |
|---------|---------|---------|
| **setuptools** | `>=68.0` | Build backend for creating wheel and sdist packages. |
| **wheel** | any | Wheel format support for `setuptools`. |

These are build-time dependencies only (specified in `[build-system]`) and are not
installed into the user's environment.
