#!/usr/bin/env bash
set -euo pipefail

# Build a versioned release ZIP from tracked repository files.
# Usage:
#   ./release.sh                # uses version from RELEASE_VERSION
#   ./release.sh 1.2.0          # uses provided version and updates RELEASE_VERSION

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VERSION_FILE="RELEASE_VERSION"
DEFAULT_VERSION="1.1"

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [version]" >&2
  exit 1
fi

if [[ $# -eq 1 ]]; then
  VERSION="$1"
  echo "$VERSION" > "$VERSION_FILE"
else
  if [[ -f "$VERSION_FILE" ]]; then
    VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
  else
    VERSION="$DEFAULT_VERSION"
    echo "$VERSION" > "$VERSION_FILE"
  fi
fi

if [[ -z "$VERSION" ]]; then
  echo "Error: release version is empty." >&2
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+(\.[0-9]+){1,2}([.-][A-Za-z0-9]+)?$ ]]; then
  echo "Error: invalid version '$VERSION'. Expected e.g. 1.1, 1.1.0 or 1.1-rc1." >&2
  exit 1
fi

OUT_DIR="$ROOT_DIR/releases"
OUT_FILE="$OUT_DIR/tinyfilemanager-${VERSION}.zip"
TMP_LIST="$(mktemp)"
trap 'rm -f "$TMP_LIST"' EXIT

mkdir -p "$OUT_DIR"

# Package tracked files to avoid accidental local artifacts.
# Never include previously generated release archives.
# Exclude development-only directories from production release bundles.
git -C "$ROOT_DIR" ls-files | grep -Ev '^(releases/|\.github/|tests/)' > "$TMP_LIST"

if [[ ! -s "$TMP_LIST" ]]; then
  echo "Error: no tracked files found to package." >&2
  exit 1
fi

rm -f "$OUT_FILE"
zip -q -9 "$OUT_FILE" -@ < "$TMP_LIST"

echo "Release created: $OUT_FILE"
