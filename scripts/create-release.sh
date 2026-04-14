#!/bin/bash
# Create a GitHub release from the current tag
# Usage: ./scripts/create-release.sh v0.4.2
set -euo pipefail

VERSION="${1:?Usage: $0 <version-tag>}"
REPO="ClawWorksCo/lasso-sandbox"

# Extract changelog entry for this version
NOTES=$(awk "/^## \[${VERSION#v}\]/{found=1;next} /^## \[/{found=0} found{print}" CHANGELOG.md)

if [ -z "$NOTES" ]; then
    echo "Warning: No changelog entry found for ${VERSION}"
    NOTES="Release ${VERSION}"
fi

echo "Creating release ${VERSION}..."
gh release create "${VERSION}" \
    --repo "${REPO}" \
    --title "LASSO ${VERSION}" \
    --notes "${NOTES}" \
    dist/*.whl dist/*.tar.gz

echo "Done: https://github.com/${REPO}/releases/tag/${VERSION}"
