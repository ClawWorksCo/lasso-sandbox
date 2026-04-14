# Integrating LASSO into CI/CD Pipelines

This directory contains ready-to-use pipeline configurations for running LASSO
in the three major CI/CD platforms. Each file is self-contained and
copy-paste ready.

| File                   | Platform       | Description                              |
|------------------------|----------------|------------------------------------------|
| `github-actions.yml`   | GitHub Actions | Multi-OS matrix, integration tests, sandbox example |
| `gitlab-ci.yml`        | GitLab CI/CD   | DinD integration, security scanning, audit collection |
| `azure-pipelines.yml`  | Azure DevOps   | Variable groups, published test results, artifact collection |


## Common Integration Patterns

### 1. Sandbox Per Pull Request

Create an isolated LASSO sandbox for every PR so that AI agent activity
is contained and auditable:

```yaml
# GitHub Actions example
- name: Sandbox agent for PR review
  run: |
    lasso init --profile development
    SANDBOX_ID=$(lasso create development --dir . --quiet)
    lasso exec "$SANDBOX_ID" -- python3 review_agent.py
    lasso audit verify ./audit/log.jsonl
    lasso stop "$SANDBOX_ID"
```

Every sandbox gets its own audit log. Upload it as an artifact so reviewers
can inspect what the agent did.

### 2. Audit Log Collection

LASSO writes HMAC-signed, hash-chained JSONL audit logs. Collect these as
pipeline artifacts with long retention for compliance:

```yaml
# Collect and retain audit evidence
- uses: actions/upload-artifact@v4
  with:
    name: audit-evidence
    path: audit/
    retention-days: 365  # DORA recommends 5-year retention
```

Export logs in CSV for compliance teams:

```bash
lasso audit export ./audit/log.jsonl --format csv --output audit-report.csv
```

### 3. Compliance Quality Gate

Use `lasso audit verify` as a pipeline gate. The command exits non-zero
if the audit chain is broken or HMAC signatures do not match:

```yaml
- name: Compliance gate
  run: |
    lasso audit verify ./audit/log.jsonl
    # Pipeline fails here if audit integrity check fails.
```

Combine with `lasso check` to verify the environment is correctly
configured before any agent runs:

```yaml
- name: Environment validation
  run: lasso check
```


## Environment Variables

LASSO reads the following environment variables. Set these in your CI/CD
platform's variable configuration (secrets, variable groups, etc.):

| Variable              | Default         | Description                                 |
|-----------------------|-----------------|---------------------------------------------|
| `LASSO_LOG_LEVEL`     | `info`          | Logging verbosity: `debug`, `info`, `warn`, `error` |
| `LASSO_AUDIT_DIR`     | `./audit`       | Directory for audit log output              |
| `LASSO_PROFILE`       | (none)          | Default profile name if not specified on CLI |
| `LASSO_HMAC_KEY`      | (auto-generated)| HMAC key for audit log signing (set via secrets) |
| `DOCKER_HOST`         | (system default)| Docker daemon address (needed for DinD setups) |

**Important**: Store `LASSO_HMAC_KEY` as a secret in your CI/CD platform.
Do not commit it to version control.

### Setting Variables by Platform

**GitHub Actions** -- use repository secrets:
```yaml
env:
  LASSO_HMAC_KEY: ${{ secrets.LASSO_HMAC_KEY }}
```

**GitLab CI** -- use CI/CD variables (masked):
```yaml
variables:
  LASSO_HMAC_KEY: $LASSO_HMAC_KEY  # Set in Settings > CI/CD > Variables
```

**Azure DevOps** -- use variable groups:
```yaml
variables:
  - group: lasso-config  # Contains LASSO_HMAC_KEY as a secret variable
```


## Docker-in-Docker Setup

LASSO integration tests and sandbox creation require a Docker (or Podman)
daemon. In CI environments, this usually means Docker-in-Docker (DinD).

### GitHub Actions

Docker is pre-installed on `ubuntu-latest` runners. No extra configuration
needed. For self-hosted runners, ensure Docker is available:

```yaml
- name: Verify Docker
  run: docker info
```

### GitLab CI

Use the `docker:27-dind` service:

```yaml
services:
  - name: docker:27-dind
    alias: docker

variables:
  DOCKER_HOST: tcp://docker:2375
  DOCKER_TLS_CERTDIR: ""
```

Your job image needs the Docker CLI. Either use `docker:27` as the base
image, or install `docker.io` in a Python image:

```yaml
before_script:
  - apt-get update && apt-get install -y docker.io
```

### Azure DevOps

Docker is pre-installed on `ubuntu-latest` hosted agents. For Windows
agents, Docker Desktop must be configured. For self-hosted agents, ensure
the agent user is in the `docker` group.


## Using LASSO as a Quality Gate

### Pre-Merge Checks

Add LASSO verification to your branch protection rules. The pipeline
should fail if any of these checks fail:

1. **`lasso check`** -- Validates the environment and configuration.
2. **`lasso audit verify`** -- Confirms audit log integrity.
3. **Unit tests pass** -- `pytest tests/ -m "not integration" -q`

### Post-Merge Deployment

After merging to main, run the full integration suite including sandbox
creation and agent execution:

```
main merge
  |
  v
[unit tests] --> [security scan] --> [integration tests] --> [deploy]
                                          |
                                          v
                                   [sandbox agent run]
                                          |
                                          v
                                   [audit verify + collect]
```

### Compliance Reporting

For regulated environments (DORA, ISO 27001), export audit logs from every
pipeline run and store them in a tamper-evident archive:

```bash
# In your pipeline's post-run step
lasso audit export ./audit/log.jsonl --format csv --output "audit-$(date +%Y%m%d-%H%M%S).csv"
```

Retain these artifacts according to your organization's data retention policy.
DORA recommends 5-year retention for operational incident records.
