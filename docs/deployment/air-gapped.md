# Air-Gapped Deployment Guide

> Deploy LASSO in environments with no internet access -- government networks,
> defense installations, central bank infrastructure, and other
> security-classified systems.

**LASSO version**: 1.6.3
**Last updated**: 2026-03-17
**Audience**: System administrators deploying LASSO on isolated networks

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Preparation (Internet-Connected Staging Machine)](#3-preparation-internet-connected-staging-machine)
4. [Installation (Air-Gapped Target Machine)](#4-installation-air-gapped-target-machine)
5. [Installation Script](#5-installation-script)
6. [Configuration for Air-Gapped Environments](#6-configuration-for-air-gapped-environments)
7. [Updating in Air-Gapped Environments](#7-updating-in-air-gapped-environments)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Overview

### What "Air-Gapped" Means

An air-gapped environment has **no connection to the internet or any untrusted
network**. All software, updates, and data must be transferred physically (USB
drives, optical media) or through a one-way data diode. These environments are
standard in:

- **Central banks** and financial regulators (DORA, ECB TIBER-EU)
- **Government classified networks** (NATO RESTRICTED and above)
- **Defense and intelligence** (NIST 800-171, ITAR)
- **Critical infrastructure** (power grids, water treatment)
- **Healthcare** with isolated research networks (HIPAA)

### What Works Fully Offline

LASSO is designed for air-gapped operation. Every core feature works without
network access:

| Feature | Offline Status | Notes |
|---------|---------------|-------|
| Sandbox creation and lifecycle | Fully offline | Container images must be pre-loaded |
| Command gating (whitelist/blacklist) | Fully offline | No external dependencies |
| Audit logging with HMAC signing | Fully offline | Signing key generated locally |
| Audit log verification | Fully offline | Self-contained verification |
| Profile management (import/export/diff) | Fully offline | TOML files, no network calls |
| Web dashboard | Fully offline | Runs on localhost, no CDN dependencies |
| Agent guardrails (CLAUDE.md generation) | Fully offline | Filesystem-only operation |

| Feature | Requires Preparation | Notes |
|---------|---------------------|-------|
| Container image building | Images must be pre-built on staging machine | `apt-get install` requires internet |
| Python package installation inside sandbox | Wheels must be pre-bundled | `pip install` requires internet |
| Profile sharing across machines | Manual file transfer | No network sync |

### What Does NOT Work Offline

- The `open` profile's restricted network mode (allowed domains are
  unreachable). Use `network.mode = "none"` instead.
- Any `pip install` or `npm install` commands inside sandboxes unless you
  pre-load packages into the container image.
- Pulling base images (`python:3.12-slim`) from Docker Hub.

---

## 2. Prerequisites

### On the Air-Gapped Target Machine

You need these installed **before** you begin:

| Requirement | Minimum Version | How to Verify |
|-------------|----------------|---------------|
| Python | 3.10+ | `python3 --version` |
| pip | 22.0+ | `pip --version` |
| Podman **or** Docker | Podman 4.0+ / Docker 24.0+ | `podman --version` or `docker --version` |

> **Recommendation**: Use Podman. It runs rootless (no daemon), which simplifies
> deployment on locked-down systems where running a Docker daemon as root is
> prohibited by policy.

If Python or a container runtime is not yet installed on the target, you must
also transfer and install those packages offline. That process is
OS-specific and outside the scope of this guide.

### On the Internet-Connected Staging Machine

| Requirement | Minimum Version |
|-------------|----------------|
| Python | 3.10+ (same minor version as target) |
| pip | 22.0+ |
| Podman **or** Docker | Same runtime as target |
| LASSO source code | This repository |
| `build` package | `pip install build` |

> **Architecture match**: The staging machine must use the **same CPU
> architecture** as the target (e.g., both x86_64 or both aarch64). Container
> images and some Python wheels are architecture-specific.

---

## 3. Preparation (Internet-Connected Staging Machine)

Perform all steps in this section on a machine that **has internet access**.

### Step 1: Clone and Build the LASSO Wheel

```bash
# Clone the repository (or copy the source)
git clone <repository-url> lasso-source
cd lasso-source

# Build the LASSO wheel
pip wheel . --no-deps -w ./dist/
```

You should see a file like `dist/lasso-0.2.0-py3-none-any.whl`.

### Step 2: Download All Python Dependencies

LASSO depends on the following packages (from `pyproject.toml`):

- `typer>=0.9`
- `rich>=13.0`
- `pydantic>=2.0`
- `tomli>=2.0`
- `tomli_w>=1.0`
- `docker>=7.0`
- `flask>=3.0`

Download wheels for all of them, including transitive dependencies:

```bash
# Download all dependencies as wheels
pip download \
    typer "rich>=13.0" "pydantic>=2.0" "tomli>=2.0" "tomli_w>=1.0" \
    "docker>=7.0" "flask>=3.0" \
    -d ./dist/ \
    --platform manylinux2014_x86_64 \
    --python-version 3.12 \
    --only-binary=:all:

# Also get source distributions as fallback for pure-Python packages
pip download \
    typer "rich>=13.0" "pydantic>=2.0" "tomli>=2.0" "tomli_w>=1.0" \
    "docker>=7.0" "flask>=3.0" \
    -d ./dist/ \
    --no-binary=:none:
```

> **Tip**: If you are unsure about the exact target platform, install LASSO
> in a clean virtual environment, then export everything:
>
> ```bash
> python3 -m venv /tmp/lasso-venv
> source /tmp/lasso-venv/bin/activate
> pip install .
> pip freeze > requirements-lock.txt
> pip download -r requirements-lock.txt -d ./dist/
> deactivate
> ```

Verify that the `dist/` directory contains `.whl` or `.tar.gz` files for every
dependency:

```bash
ls dist/
# Expected: lasso-0.2.0-py3-none-any.whl, typer-*.whl, rich-*.whl,
#           pydantic-*.whl, pydantic_core-*.whl, tomli-*.whl,
#           tomli_w-*.whl, docker-*.whl, flask-*.whl, and their
#           transitive dependencies (click, markdown-it-py, etc.)
```

### Step 3: Build and Export Container Images

LASSO builds custom container images per profile. Each image contains only the
tools whitelisted in that profile's configuration. You must build these images
on the staging machine and export them as tar archives.

```bash
# Create a temporary working directory for image builds
mkdir -p /tmp/lasso-staging

# Install LASSO on the staging machine
pip install .

# Build images by creating sandboxes (this triggers image builds)
# Each profile gets a custom image with only its whitelisted tools installed.
lasso create standard --dir /tmp/lasso-staging
lasso create open --dir /tmp/lasso-staging
lasso create offline --dir /tmp/lasso-staging

# Stop the sandboxes (we only needed them to trigger image builds)
lasso stop all
```

Now identify the image tags and export them:

```bash
# List LASSO-managed images
# Image tags follow the pattern: lasso-<config-hash-first-12-chars>
podman images --filter label=managed-by=lasso --format "{{.Repository}}:{{.Tag}}"

# Create the images directory
mkdir -p ./images/

# Export each image (replace tags with actual output from the command above)
# With Podman:
podman save lasso-standard:latest -o ./images/lasso-standard.tar
podman save lasso-open:latest -o ./images/lasso-open.tar
podman save lasso-offline:latest -o ./images/lasso-offline.tar

# With Docker:
# docker save lasso-standard:latest -o ./images/lasso-standard.tar
# docker save lasso-open:latest -o ./images/lasso-open.tar
# docker save lasso-offline:latest -o ./images/lasso-offline.tar
```

> **Image naming**: LASSO generates image tags using a hash of the profile
> configuration (e.g., `lasso-a1b2c3d4e5f6`). The exact tag depends on your
> profile settings. Use `podman images --filter label=managed-by=lasso` to see
> the actual tags.

You must also export the **base image** used by LASSO-built Dockerfiles. All
built-in profiles use `python:3.12-slim`:

```bash
# Pull and export the base image
podman pull python:3.12-slim
podman save python:3.12-slim -o ./images/python-3.12-slim.tar
```

> **Why the base image?** If you later need to rebuild images on the
> air-gapped machine (for example, after modifying a profile), the base image
> must be available locally. Without it, `FROM python:3.12-slim` in the
> generated Dockerfile will fail.

### Step 4: Export Profiles

Export each profile as a standalone TOML file with integrity metadata:

```bash
mkdir -p ./profiles/

lasso profile export standard --output ./profiles/standard.toml
lasso profile export open --output ./profiles/open.toml
lasso profile export offline --output ./profiles/offline.toml
```

Each exported file includes a `[lasso_metadata]` section with a SHA-256
`config_hash` and an `exported_at` timestamp for integrity verification during
import.

### Step 5: Generate an Audit Signing Key

If you use HMAC-signed audit logs (recommended for compliance), pre-generate
the signing key on a trusted machine:

```bash
python3 -c "
import secrets, base64
key = secrets.token_bytes(32)
print(base64.b64encode(key).decode())
" > ./audit-signing-key.b64
```

Store this key securely. You will copy it to the air-gapped machine and
configure LASSO to use it.

### Step 6: Bundle Everything for Transfer

```bash
# Create the deployment bundle
BUNDLE="lasso-airgap-v1.6.3"
mkdir -p "${BUNDLE}"

# Copy all components
cp -r dist/     "${BUNDLE}/"   # Python wheels
cp -r images/   "${BUNDLE}/"   # Container images
cp -r profiles/ "${BUNDLE}/"   # Profile TOML files
cp -r docs/     "${BUNDLE}/"   # Documentation (including this guide)

# Copy the audit signing key
cp audit-signing-key.b64 "${BUNDLE}/"

# Copy the install script (see Section 5)
cp install.sh "${BUNDLE}/"
chmod +x "${BUNDLE}/install.sh"

# Create the archive
tar czf "${BUNDLE}.tar.gz" "${BUNDLE}/"

# Print the checksum -- record this and verify after transfer
sha256sum "${BUNDLE}.tar.gz"
```

Record the SHA-256 checksum. You will verify it after transferring to the
air-gapped machine to confirm no tampering or corruption occurred during
transfer.

---

## 4. Installation (Air-Gapped Target Machine)

### Step 1: Transfer the Bundle

Transfer `lasso-airgap-v1.6.3.tar.gz` to the air-gapped machine using your
organization's approved method:

- **USB drive** (most common for classified environments)
- **Optical media** (CD/DVD, write-once for tamper evidence)
- **Data diode** (one-way network transfer device)
- **Cross-domain solution** (CDS) if your environment uses one

### Step 2: Verify the Bundle Integrity

```bash
# Verify the checksum matches the value recorded during preparation
sha256sum lasso-airgap-v1.6.3.tar.gz
# Compare output with the checksum from Step 6 of the preparation phase

# Extract
tar xzf lasso-airgap-v1.6.3.tar.gz
cd lasso-airgap-v1.6.3
```

### Step 3: Install Python Packages

```bash
# Install LASSO and all dependencies from local wheels only
# --no-index prevents pip from reaching out to PyPI
pip install --no-index --find-links ./dist/ lasso
```

Verify the installation:

```bash
lasso --version
# Expected: lasso 0.2.0
```

### Step 4: Load Container Images

```bash
# Load the base image first (required if you ever rebuild profile images)
podman load -i ./images/python-3.12-slim.tar

# Load the pre-built LASSO sandbox images
podman load -i ./images/lasso-standard.tar
podman load -i ./images/lasso-open.tar
podman load -i ./images/lasso-offline.tar
```

With Docker, replace `podman load` with `docker load`.

Verify the images loaded correctly:

```bash
podman images --filter label=managed-by=lasso
# You should see all three LASSO images listed
```

### Step 5: Import Profiles

```bash
lasso profile import ./profiles/standard.toml
lasso profile import ./profiles/open.toml
lasso profile import ./profiles/offline.toml
```

LASSO verifies the `config_hash` in each file's `[lasso_metadata]` section
during import. If the hash does not match, you will see a warning indicating
the file may have been modified.

Verify:

```bash
lasso profile list
# Expected: standard, open, offline
```

### Step 6: Configure the Audit Signing Key

```bash
# Create the LASSO config directory
mkdir -p ~/.lasso

# Store the signing key
cp ./audit-signing-key.b64 ~/.lasso/audit-signing-key.b64
chmod 600 ~/.lasso/audit-signing-key.b64
```

Set the environment variable so LASSO finds the key:

```bash
# Add to your shell profile (~/.bashrc or ~/.zshrc)
export LASSO_AUDIT_KEY_FILE="${HOME}/.lasso/audit-signing-key.b64"
```

### Step 7: Run the System Check

```bash
lasso check
```

Expected output:

```
LASSO System Check
------------------
Python version:   3.12.x     [OK]
Container runtime: podman 4.x [OK]
Profiles loaded:   3          [OK]
Audit signing:     configured [OK]
Network:           isolated   [OK]
```

### Step 8: Verify End-to-End

Create a test sandbox to confirm everything works:

```bash
# Create a standard sandbox
lasso create standard --dir /tmp/lasso-test

# Run a command inside it
lasso exec <sandbox-id> -- echo "Air-gapped deployment successful"

# Check the audit log
lasso audit view ./audit/log.jsonl

# Stop and clean up
lasso stop all
rm -rf /tmp/lasso-test
```

---

## 5. Installation Script

Save the following as `install.sh` in the deployment bundle. It automates
Steps 3 through 7 from the installation section.

```bash
#!/usr/bin/env bash
#
# install.sh -- LASSO Air-Gapped Installer
#
# Usage: ./install.sh [--runtime podman|docker] [--skip-images] [--prefix /path]
#
# This script installs LASSO from a pre-built bundle on an air-gapped machine.
# Run it from inside the extracted lasso-airgap-v1.6.3/ directory.
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="auto"
SKIP_IMAGES=false
PREFIX=""
VERBOSE=false

# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runtime)
            RUNTIME="$2"; shift 2 ;;
        --skip-images)
            SKIP_IMAGES=true; shift ;;
        --prefix)
            PREFIX="$2"; shift 2 ;;
        --verbose|-v)
            VERBOSE=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--runtime podman|docker] [--skip-images] [--prefix /path]"
            echo ""
            echo "Options:"
            echo "  --runtime <podman|docker>  Specify container runtime (default: auto-detect)"
            echo "  --skip-images              Skip loading container images"
            echo "  --prefix <path>            Install Python packages to a custom prefix"
            echo "  --verbose, -v              Enable verbose output"
            exit 0 ;;
        *)
            die "Unknown option: $1. Use --help for usage." ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "LASSO Air-Gapped Installer"
info "=========================="
echo ""

# Check we are in the right directory
if [[ ! -d "${SCRIPT_DIR}/dist" ]]; then
    die "dist/ directory not found. Run this script from inside the deployment bundle."
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    die "python3 not found. Install Python 3.10+ before running this script."
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 10 ]]; then
    die "Python 3.10+ required. Found: python3 ${PYTHON_VERSION}"
fi
info "Python ${PYTHON_VERSION} detected"

# Detect container runtime
if [[ "$RUNTIME" == "auto" ]]; then
    if command -v podman &>/dev/null; then
        RUNTIME="podman"
    elif command -v docker &>/dev/null; then
        RUNTIME="docker"
    else
        die "No container runtime found. Install Podman or Docker first."
    fi
fi

if ! command -v "$RUNTIME" &>/dev/null; then
    die "${RUNTIME} not found in PATH."
fi
info "Container runtime: ${RUNTIME} ($(${RUNTIME} --version 2>/dev/null || echo 'version unknown'))"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Install Python packages
# ---------------------------------------------------------------------------
info "Step 1/5: Installing Python packages from local wheels..."

PIP_ARGS=(--no-index --find-links "${SCRIPT_DIR}/dist/")
if [[ -n "$PREFIX" ]]; then
    PIP_ARGS+=(--prefix "$PREFIX")
fi

pip install "${PIP_ARGS[@]}" lasso || die "Failed to install LASSO. Check dist/ contents."

INSTALLED_VERSION=$(python3 -c "from lasso import __version__; print(__version__)" 2>/dev/null || echo "unknown")
info "LASSO ${INSTALLED_VERSION} installed"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Load container images
# ---------------------------------------------------------------------------
if [[ "$SKIP_IMAGES" == true ]]; then
    warn "Step 2/5: Skipping container image loading (--skip-images)"
else
    info "Step 2/5: Loading container images..."

    if [[ ! -d "${SCRIPT_DIR}/images" ]]; then
        warn "images/ directory not found. Skipping image loading."
    else
        IMAGE_COUNT=0
        FAIL_COUNT=0

        for tar_file in "${SCRIPT_DIR}"/images/*.tar; do
            if [[ ! -f "$tar_file" ]]; then
                continue
            fi

            image_name=$(basename "$tar_file" .tar)
            info "  Loading ${image_name}..."

            if ${RUNTIME} load -i "$tar_file" 2>/dev/null; then
                IMAGE_COUNT=$((IMAGE_COUNT + 1))
            else
                warn "  Failed to load ${image_name}"
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
        done

        info "  Loaded ${IMAGE_COUNT} images (${FAIL_COUNT} failures)"
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: Import profiles
# ---------------------------------------------------------------------------
info "Step 3/5: Importing profiles..."

if [[ ! -d "${SCRIPT_DIR}/profiles" ]]; then
    warn "profiles/ directory not found. Skipping profile import."
else
    PROFILE_COUNT=0

    for toml_file in "${SCRIPT_DIR}"/profiles/*.toml; do
        if [[ ! -f "$toml_file" ]]; then
            continue
        fi

        profile_name=$(basename "$toml_file" .toml)
        info "  Importing ${profile_name}..."

        if lasso profile import "$toml_file" 2>/dev/null; then
            PROFILE_COUNT=$((PROFILE_COUNT + 1))
        else
            warn "  Failed to import ${profile_name}"
        fi
    done

    info "  Imported ${PROFILE_COUNT} profiles"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Configure audit signing key
# ---------------------------------------------------------------------------
info "Step 4/5: Configuring audit signing key..."

LASSO_DIR="${HOME}/.lasso"
mkdir -p "${LASSO_DIR}"

if [[ -f "${SCRIPT_DIR}/audit-signing-key.b64" ]]; then
    cp "${SCRIPT_DIR}/audit-signing-key.b64" "${LASSO_DIR}/audit-signing-key.b64"
    chmod 600 "${LASSO_DIR}/audit-signing-key.b64"
    info "  Signing key installed to ${LASSO_DIR}/audit-signing-key.b64"

    # Add to shell profile if not already present
    SHELL_RC="${HOME}/.bashrc"
    if [[ -f "${HOME}/.zshrc" ]] && [[ "$SHELL" == */zsh ]]; then
        SHELL_RC="${HOME}/.zshrc"
    fi

    ENV_LINE='export LASSO_AUDIT_KEY_FILE="${HOME}/.lasso/audit-signing-key.b64"'
    if ! grep -q "LASSO_AUDIT_KEY_FILE" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# LASSO audit signing key" >> "$SHELL_RC"
        echo "$ENV_LINE" >> "$SHELL_RC"
        info "  Added LASSO_AUDIT_KEY_FILE to ${SHELL_RC}"
    fi

    # Export for this session
    export LASSO_AUDIT_KEY_FILE="${LASSO_DIR}/audit-signing-key.b64"
else
    warn "  No audit-signing-key.b64 found in bundle. Skipping."
    warn "  Generate one with: python3 -c \"import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())\""
fi
echo ""

# ---------------------------------------------------------------------------
# Step 5: Verify installation
# ---------------------------------------------------------------------------
info "Step 5/5: Verifying installation..."

ERRORS=0

# Check lasso command
if command -v lasso &>/dev/null; then
    info "  lasso command:    OK"
else
    error "  lasso command:    NOT FOUND"
    ERRORS=$((ERRORS + 1))
fi

# Check container runtime
if ${RUNTIME} info &>/dev/null; then
    info "  ${RUNTIME}:          OK"
else
    error "  ${RUNTIME}:          NOT RESPONDING"
    ERRORS=$((ERRORS + 1))
fi

# Check images
if [[ "$SKIP_IMAGES" != true ]]; then
    IMAGE_LIST=$(${RUNTIME} images --filter label=managed-by=lasso --format "{{.Repository}}" 2>/dev/null | wc -l)
    if [[ "$IMAGE_LIST" -gt 0 ]]; then
        info "  Container images: ${IMAGE_LIST} loaded"
    else
        warn "  Container images: none found with lasso label"
    fi
fi

# Check profiles
PROFILE_LIST=$(lasso profile list 2>/dev/null | grep -c "│" || echo "0")
info "  Profiles:         available"

# Run lasso check
info "  Running lasso check..."
if lasso check 2>/dev/null; then
    info "  System check:     PASSED"
else
    warn "  System check:     see output above"
fi

echo ""
if [[ "$ERRORS" -eq 0 ]]; then
    info "========================================="
    info "LASSO air-gapped installation complete!"
    info "========================================="
    echo ""
    info "Next steps:"
    info "  1. Open a new terminal (or run: source ${SHELL_RC})"
    info "  2. Run: lasso create standard --dir /tmp/test"
    info "  3. Run: lasso check"
else
    error "Installation completed with ${ERRORS} error(s). Review the output above."
    exit 1
fi
```

Make the script executable when including it in the bundle:

```bash
chmod +x install.sh
```

---

## 6. Configuration for Air-Gapped Environments

### Network Mode Must Be "none"

In an air-gapped environment, the `open` profile's default
`network.mode = "restricted"` is meaningless -- the allowed domains are
unreachable. Override it to `"none"` for all profiles:

```toml
# In your profile TOML file
[network]
mode = "none"
```

The `standard` and `offline` profiles already default to
`network.mode = "none"`, so they require no changes.

### DNS Configuration Is Irrelevant

You can safely omit or leave empty any DNS-related settings. With
`network.mode = "none"`, the container has no network stack and DNS
resolution is not attempted.

### Audit Signing Key

For DORA and ISO 27001 compliance, enable signed audit entries:

```toml
[audit]
enabled = true
include_command_output = true
include_file_diffs = true
sign_entries = true
```

The signing key must be stored at the path referenced by
`LASSO_AUDIT_KEY_FILE`. Protect this file with restrictive permissions
(`chmod 600`). If the key is compromised, generate a new one and rotate it.

### Dashboard Runs on Localhost Only

The LASSO web dashboard binds to `127.0.0.1:8080` by default. This is correct
for air-gapped use -- no changes needed:

```bash
lasso dashboard
# Accessible at http://localhost:8080
```

If you need to expose the dashboard to other machines on the isolated network,
bind to the appropriate interface:

```bash
lasso dashboard --host 0.0.0.0 --port 8080
```

> **Warning**: Only do this on a trusted, isolated network segment. The
> dashboard does not currently implement authentication.

### Pre-Loading Python Packages for Sandbox Use

If agents running inside sandboxes need Python packages (e.g., `pandas`,
`numpy`), you have two options:

**Option A: Bake packages into the container image** (recommended)

On the staging machine, create a custom Dockerfile that extends the LASSO base
image:

```dockerfile
FROM python:3.12-slim

LABEL managed-by=lasso
LABEL lasso-profile=offline-custom

# Copy pre-downloaded wheels into the image
COPY wheels/ /tmp/wheels/

# Install from local wheels
RUN pip install --no-index --find-links /tmp/wheels/ \
    pandas numpy scipy matplotlib \
    && rm -rf /tmp/wheels/

RUN useradd -m -u 1000 -s /bin/bash sandbox
WORKDIR /workspace
USER sandbox
CMD ["sleep", "infinity"]
```

Build and export the custom image on the staging machine, then load it on the
target.

**Option B: Mount a wheels directory into the sandbox**

Place wheels on the host filesystem and mount them into the container:

```toml
[filesystem]
working_dir = "/path/to/project"
# Additional mount for offline packages
# Configure via the container backend directly
```

Then inside the sandbox: `pip install --no-index --find-links /mnt/wheels pandas`

---

## 7. Updating in Air-Gapped Environments

### Update Process Overview

Updating LASSO in an air-gapped environment follows the same preparation-transfer-install
cycle as the initial deployment. Plan for this process to take **1-2 hours**
including verification.

### Step 1: Build Updated Artifacts (Staging Machine)

```bash
cd lasso-source

# Pull latest changes
git pull

# Build the new wheel
pip wheel . --no-deps -w ./dist-update/

# Download updated dependencies
pip download -r <(pip freeze) -d ./dist-update/

# Rebuild container images if profiles changed
lasso create standard --dir /tmp/lasso-staging
lasso create open --dir /tmp/lasso-staging
lasso create offline --dir /tmp/lasso-staging
lasso stop all

# Export updated images
mkdir -p ./images-update/
podman images --filter label=managed-by=lasso --format "{{.Repository}}:{{.Tag}}" | \
    while read -r image; do
        safe_name=$(echo "$image" | tr '/:' '-')
        podman save "$image" -o "./images-update/${safe_name}.tar"
    done

# Export updated profiles
mkdir -p ./profiles-update/
lasso profile export standard --output ./profiles-update/standard.toml
lasso profile export open --output ./profiles-update/open.toml
lasso profile export offline --output ./profiles-update/offline.toml
```

### Step 2: Bundle and Transfer

```bash
BUNDLE="lasso-update-v1.6.3"
mkdir -p "${BUNDLE}"
cp -r dist-update/     "${BUNDLE}/dist/"
cp -r images-update/   "${BUNDLE}/images/"
cp -r profiles-update/ "${BUNDLE}/profiles/"
cp install.sh          "${BUNDLE}/"
tar czf "${BUNDLE}.tar.gz" "${BUNDLE}/"
sha256sum "${BUNDLE}.tar.gz"
```

Transfer using your approved method.

### Step 3: Install on Air-Gapped Machine

```bash
# Verify checksum
sha256sum lasso-update-v1.6.3.tar.gz

# Extract
tar xzf lasso-update-v1.6.3.tar.gz
cd lasso-update-v1.6.3

# Stop any running sandboxes
lasso stop all

# Upgrade LASSO
pip install --no-index --find-links ./dist/ --upgrade lasso

# Load updated images
for tar_file in ./images/*.tar; do
    podman load -i "$tar_file"
done

# Import updated profiles (versioned -- old versions are archived automatically)
for toml_file in ./profiles/*.toml; do
    lasso profile import "$toml_file"
done

# Verify
lasso --version
lasso check
```

### Profile Schema Migration

If a LASSO update changes the profile schema (e.g., new required fields,
renamed sections), the `lasso profile import` command validates the profile
structure and reports errors. In that case:

1. Check the release notes for migration instructions.
2. Edit the exported TOML files on the staging machine to match the new schema.
3. Re-export and re-transfer.

LASSO's versioned profile system (see `lasso.config.sharing`) automatically
archives previous profile versions to `~/.lasso/profiles/.history/<name>/`,
so you can always roll back:

```bash
# List archived versions of a profile
ls ~/.lasso/profiles/.history/standard/
# v1_2026-03-17T10-00-00.toml  v2_2026-03-18T14-30-00.toml
```

---

## 8. Troubleshooting

### "No module named 'lasso'"

**Cause**: `pip install` succeeded but the package is not on your `PATH`.

**Fix**:
```bash
# Check where pip installed it
pip show lasso

# If installed to a user directory, ensure it is on PATH
export PATH="${HOME}/.local/bin:${PATH}"
```

### "pip cannot find distribution for lasso"

**Cause**: The `dist/` directory is missing the LASSO wheel or a required
dependency.

**Fix**:
```bash
# List what is in dist/
ls dist/*.whl dist/*.tar.gz

# Verify the LASSO wheel is present
ls dist/lasso-*.whl

# If missing, rebuild on the staging machine and re-transfer
```

### "ImageNotFound" or "image not found" When Creating a Sandbox

**Cause**: The container image was not loaded, or the image tag does not match
what the profile expects.

**Fix**:
```bash
# List loaded images
podman images --filter label=managed-by=lasso

# Check what tag LASSO expects for a profile
python3 -c "
from lasso.config.defaults import BUILTIN_PROFILES
from lasso.backends.image_builder import image_tag
profile = BUILTIN_PROFILES['standard']('.')
print(image_tag(profile))
"
# Output: lasso-<hash>

# If the tags don't match, the profile was modified after the image was built.
# Rebuild on the staging machine with the same profile configuration.
```

### "Error loading image: open /path/to/image.tar: permission denied"

**Cause**: File permissions on the tar archive are too restrictive.

**Fix**:
```bash
chmod 644 images/*.tar
podman load -i images/lasso-standard.tar
```

### Container Runtime Not Responding

**Cause**: The Podman or Docker daemon/socket is not running.

**Fix**:
```bash
# For Podman (rootless)
systemctl --user start podman.socket
podman info

# For Docker
sudo systemctl start docker
docker info
```

### Audit Log Verification Fails

**Cause**: The signing key on the target machine does not match the key used
when the log entries were created.

**Fix**:
```bash
# Verify the key file exists and has the correct permissions
ls -la ~/.lasso/audit-signing-key.b64

# Check the environment variable is set
echo "$LASSO_AUDIT_KEY_FILE"

# Verify the audit log
lasso audit verify ./audit/log.jsonl
```

If the key has been rotated, old log entries signed with the previous key
will fail verification. This is expected behavior -- it indicates a key
change, not tampering. Document key rotation dates in your operational log.

### "apt-get update" Fails Inside Container

**Cause**: You are attempting to rebuild a container image on the air-gapped
machine. The generated Dockerfile runs `apt-get update`, which requires
internet access.

**Fix**: Do not rebuild images on the air-gapped machine unless you have
pre-loaded the base image and all required `.deb` packages. The recommended
approach is to build all images on the staging machine and transfer them as
tar archives.

If you must rebuild, create a local APT mirror on the air-gapped network and
configure the container's sources.list to use it.

### Dashboard Shows No Sandboxes

**Cause**: The dashboard reads from the sandbox registry, which tracks only
sandboxes created in the current session.

**Fix**:
```bash
# Create a sandbox first
lasso create standard --dir /path/to/project

# Then open the dashboard
lasso dashboard
```

### Verifying the Full Installation

Run this sequence to confirm every component is working:

```bash
# 1. Version check
lasso --version

# 2. System check
lasso check

# 3. List profiles
lasso profile list

# 4. Create a sandbox
lasso create standard --dir /tmp/verify-test

# 5. Execute a command
lasso exec "$(lasso status --json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data[0]['id'] if data else '')
")" -- echo "LASSO is operational"

# 6. View the audit log
lasso audit view ./audit/log.jsonl

# 7. Clean up
lasso stop all
rm -rf /tmp/verify-test

echo "All checks passed."
```

---

## Quick Reference Card

Print this section and keep it with the deployment bundle.

```
LASSO Air-Gapped Deployment -- Quick Reference
===============================================

INSTALL:
  tar xzf lasso-airgap-v1.6.3.tar.gz
  cd lasso-airgap-v1.6.3
  ./install.sh

VERIFY:
  lasso --version
  lasso check
  lasso create standard --dir /tmp/test

DAILY USE:
  lasso create <profile> --dir <path>    Create sandbox
  lasso exec <id> -- <command>           Run command
  lasso shell --dir .    REPL mode
  lasso stop all                         Stop all sandboxes
  lasso audit view <log-file>            View audit trail
  lasso audit verify <log-file>          Verify integrity
  lasso dashboard                        Web UI (:8080)

UPDATE:
  lasso stop all
  pip install --no-index --find-links ./dist/ --upgrade lasso
  podman load -i ./images/<image>.tar
  lasso profile import ./profiles/<name>.toml
  lasso check

TROUBLESHOOT:
  lasso check                            System diagnostics
  podman images --filter label=managed-by=lasso
  pip show lasso
  echo $LASSO_AUDIT_KEY_FILE
```
