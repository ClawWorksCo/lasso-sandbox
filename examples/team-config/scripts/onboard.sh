#!/usr/bin/env bash
# LASSO team onboarding script
# Run this once on a new developer machine to set up LASSO with team profiles.
#
# Usage: bash scripts/onboard.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LASSO_CONFIG_DIR="${HOME}/.lasso"
LASSO_PROFILE_DIR="${LASSO_CONFIG_DIR}/profiles"

echo "=== LASSO Team Onboarding ==="
echo ""

# 1. Check Python version
PYTHON_VERSION=$(python3 --version 2>/dev/null | cut -d' ' -f2)
if [ -z "$PYTHON_VERSION" ]; then
    echo "ERROR: python3 not found. Install Python 3.10+."
    exit 1
fi
echo "[OK] Python $PYTHON_VERSION"

# 2. Install lasso-sandbox
echo ""
echo "Installing lasso-sandbox..."
pip install --quiet lasso-sandbox>=1.6.3
echo "[OK] lasso-sandbox installed"

# 3. Create config directory
mkdir -p "$LASSO_PROFILE_DIR"

# 4. Copy team profiles
echo ""
echo "Copying team profiles..."
cp "$SCRIPT_DIR/profiles/"*.toml "$LASSO_PROFILE_DIR/"
echo "[OK] Profiles copied to $LASSO_PROFILE_DIR"

# 5. Copy team config (if not already present)
if [ ! -f "$LASSO_CONFIG_DIR/config.toml" ]; then
    cp "$SCRIPT_DIR/lasso-config.toml" "$LASSO_CONFIG_DIR/config.toml"
    echo "[OK] Config copied to $LASSO_CONFIG_DIR/config.toml"
else
    echo "[SKIP] Config already exists at $LASSO_CONFIG_DIR/config.toml"
fi

# 6. Check container runtime
echo ""
echo "Checking container runtime..."
if command -v docker &>/dev/null; then
    echo "[OK] Docker found: $(docker --version)"
elif command -v podman &>/dev/null; then
    echo "[OK] Podman found: $(podman --version)"
else
    echo "WARNING: No container runtime found. Install Docker Desktop or Podman."
    echo "         See: docs/workflows/windows-setup.md"
fi

# 7. Run lasso doctor
echo ""
echo "Running lasso doctor..."
lasso check || true

echo ""
echo "=== Onboarding complete ==="
echo ""
echo "Next steps:"
echo "  lasso create team-development --dir .    # Start a development sandbox"
echo "  lasso create team-strict --dir .          # Start a compliance sandbox"
echo "  lasso status                              # List running sandboxes"
