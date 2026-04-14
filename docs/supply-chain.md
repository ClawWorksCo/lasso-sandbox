# LASSO — Supply Chain Security: SBOM and Trusted Publisher

**Document version:** 1.0
**Last updated:** 2026-03-24
**Audience:** Release engineers, security teams, CI/CD maintainers

---

## Overview

This document covers two supply chain security practices for the LASSO project:

1. **SBOM (Software Bill of Materials)** — generating a machine-readable inventory of all dependencies
2. **Trusted Publisher** — configuring PyPI to accept packages only from verified GitHub Actions workflows

Both practices strengthen the integrity of LASSO's distribution pipeline and support compliance requirements (DORA Art. 28, EU Cyber Resilience Act, US Executive Order 14028).

---

## 1. Software Bill of Materials (SBOM)

### 1.1 What Is an SBOM?

An SBOM is a formal, machine-readable inventory of all components (direct and transitive dependencies) included in a software package. For regulated environments, SBOMs provide:

- **Vulnerability tracking** — map CVEs to specific dependency versions in your deployment
- **License compliance** — verify all dependencies meet organizational license policies
- **Incident response** — quickly determine if a newly disclosed vulnerability affects your installation
- **Regulatory compliance** — DORA Art. 28 requires third-party ICT risk management, which includes knowing what software components are in use

### 1.2 Generating an SBOM with CycloneDX

[CycloneDX](https://cyclonedx.org/) is an OWASP standard for SBOMs. The `cyclonedx-bom` tool generates SBOMs from Python project metadata.

#### Installation

```bash
pip install cyclonedx-bom
```

#### Generate from Requirements

```bash
# From a requirements file
pip install cyclonedx-bom
cyclonedx-py requirements -i requirements.txt -o sbom.json --format json

# From the current environment (captures exact installed versions)
cyclonedx-py environment -o sbom.json --format json

# XML format (CycloneDX native)
cyclonedx-py requirements -i requirements.txt -o sbom.xml --format xml
```

#### Generate from pyproject.toml

For LASSO's `pyproject.toml`-based build:

```bash
# First, generate a pinned requirements file from the lock/installed state
pip freeze > requirements-lock.txt

# Then generate the SBOM from the pinned versions
cyclonedx-py requirements -i requirements-lock.txt -o sbom.json --format json
```

### 1.3 SBOM in CI (GitHub Actions)

Add SBOM generation to the release workflow (`.github/workflows/release.yml`):

```yaml
- name: Generate SBOM
  run: |
    pip install cyclonedx-bom
    pip freeze > requirements-lock.txt
    cyclonedx-py requirements -i requirements-lock.txt -o sbom.json --format json

- name: Upload SBOM as release artifact
  uses: softprops/action-gh-release@v2
  with:
    files: |
      dist/*.whl
      dist/*.tar.gz
      sbom.json
```

### 1.4 SBOM Verification

Consumers of LASSO can verify the SBOM against their vulnerability databases:

```bash
# Using grype (Anchore)
grype sbom:sbom.json

# Using osv-scanner (Google)
osv-scanner --sbom sbom.json

# Using trivy (Aqua Security)
trivy sbom sbom.json
```

### 1.5 SBOM Contents for LASSO

A typical LASSO SBOM includes:

| Category | Examples |
|---|---|
| Core runtime | `click`/`typer`, `pydantic`, `tomli`/`tomllib`, `docker` SDK |
| Web/API | `flask`, `jinja2`, `werkzeug` |
| Crypto | `hmac` (stdlib), `hashlib` (stdlib) — no external crypto deps |
| Testing (dev only) | `pytest`, `pytest-cov`, `ruff` |
| Build (dev only) | `build`, `twine`, `setuptools` |

The SBOM should be generated from the **production** dependency set, not the development environment. Use `pip install lasso-sandbox && pip freeze` in a clean virtual environment for the most accurate production SBOM.

---

## 2. PyPI Trusted Publisher

### 2.1 What Is Trusted Publisher?

[Trusted Publishers](https://docs.pypi.org/trusted-publishers/) is PyPI's implementation of OpenID Connect (OIDC) for package publishing. Instead of storing a long-lived API token as a GitHub secret, PyPI verifies that the publish request comes from a specific GitHub Actions workflow in a specific repository.

**Benefits over API tokens:**

- No long-lived secrets to rotate or leak
- Publishing is bound to a specific repository, workflow, and (optionally) environment
- Automatic — GitHub Actions provides the OIDC token; no manual token management
- Auditable — PyPI logs which workflow published each version

### 2.2 Setting Up Trusted Publisher for LASSO

#### Step 1: Configure PyPI

1. Go to [pypi.org/manage/project/lasso-sandbox/settings/publishing/](https://pypi.org/manage/project/lasso-sandbox/settings/publishing/)
2. Add a new Trusted Publisher:
   - **Owner:** `ClawWorksCo`
   - **Repository:** `lasso-sandbox`
   - **Workflow name:** `release.yml`
   - **Environment:** `release` (optional but recommended)

#### Step 2: Update the Release Workflow

Replace the `twine upload` step with the PyPA trusted publishing action. Update `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write
  id-token: write    # Required for Trusted Publisher OIDC

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: release    # Must match PyPI Trusted Publisher config

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install build tools
        run: pip install build

      - name: Build package
        run: python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        # No token needed — uses OIDC Trusted Publisher

      - name: Generate SBOM
        run: |
          pip install cyclonedx-bom
          pip install dist/*.whl
          pip freeze > requirements-lock.txt
          cyclonedx-py requirements -i requirements-lock.txt -o sbom.json --format json

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            dist/*
            sbom.json
```

#### Step 3: Remove the `PYPI_TOKEN` Secret

Once Trusted Publisher is configured and verified:

1. Publish one release using the new workflow to confirm it works
2. Delete the `PYPI_TOKEN` secret from GitHub repository settings
3. Revoke the API token on PyPI

#### Step 4: Create the GitHub Environment

1. Go to the repository Settings > Environments
2. Create an environment named `release`
3. (Optional) Add protection rules:
   - Required reviewers for manual release approval
   - Restrict to the `main` branch only
   - Deployment branch restriction: tags matching `v*`

### 2.3 How It Works

```
Tag push (v0.5.0)
  -> GitHub Actions starts release.yml
    -> GitHub mints OIDC token (claims: repo, workflow, ref, environment)
      -> pypa/gh-action-pypi-publish sends token to PyPI
        -> PyPI verifies: repo=ClawWorksCo/lasso-sandbox, workflow=release.yml, env=release
          -> PyPI accepts the upload (no API token involved)
```

### 2.4 Verifying Published Packages

After publishing with Trusted Publisher, PyPI shows provenance information:

- The "Provenance" section on the package page links to the exact GitHub Actions run
- Users can verify the package was built from the tagged source code
- `pip install --require-hashes` can be combined with the SBOM for full verification

---

## 3. Combined Supply Chain Workflow

The recommended release process integrates both SBOM generation and Trusted Publisher:

```
Developer tags v0.5.0
  -> CI runs release.yml
    -> Build .whl and .tar.gz
    -> Publish to PyPI via Trusted Publisher (OIDC, no token)
    -> Generate SBOM from installed package
    -> Create GitHub Release with artifacts:
        - lasso_sandbox-0.5.0-py3-none-any.whl
        - lasso_sandbox-0.5.0.tar.gz
        - sbom.json
    -> (Future) Run scripts/create-release.sh for changelog extraction
```

### 3.1 Manual Release Script

For releases created outside CI (hotfixes, pre-releases), use the `scripts/create-release.sh` script:

```bash
# Build
python -m build

# Generate SBOM
pip install cyclonedx-bom
pip install dist/*.whl
pip freeze > requirements-lock.txt
cyclonedx-py requirements -i requirements-lock.txt -o sbom.json --format json

# Create GitHub release (requires gh CLI and CHANGELOG.md entry)
./scripts/create-release.sh v0.5.0
```

Note: Manual releases still require a PyPI API token (Trusted Publisher only works from GitHub Actions). Prefer the CI workflow for production releases.

---

## 4. References

| Resource | URL |
|---|---|
| CycloneDX Python tool | https://github.com/CycloneDX/cyclonedx-python |
| CycloneDX specification | https://cyclonedx.org/specification/overview/ |
| PyPI Trusted Publishers | https://docs.pypi.org/trusted-publishers/ |
| PyPA publish action | https://github.com/pypa/gh-action-pypi-publish |
| SLSA framework | https://slsa.dev/ |
| DORA Art. 28 (third-party risk) | Regulation (EU) 2022/2554, Article 28 |
| US EO 14028 (SBOM requirement) | Executive Order 14028, Section 4(e) |
| NIST SBOM guidance | https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security |

---

## Related Documents

- [Release Workflow](../.github/workflows/release.yml) — current CI release pipeline
- [Security Policy](../SECURITY.md) — vulnerability reporting
- [Dependencies](./dependencies.md) — dependency policy and update process
