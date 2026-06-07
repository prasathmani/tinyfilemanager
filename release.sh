#!/usr/bin/env bash
set -euo pipefail

# Build a versioned release ZIP from tracked repository files.
# Usage:
#   ./release.sh                # uses version from RELEASE_VERSION
#   ./release.sh 1.2.0          # uses provided version, then updates RELEASE_VERSION
#   ./release.sh --include-local-config [version]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VERSION_FILE="RELEASE_VERSION"
DEFAULT_VERSION="1.1"
INCLUDE_LOCAL_CONFIG=false

VERSION=""
for arg in "$@"; do
  case "$arg" in
    --include-local-config)
      INCLUDE_LOCAL_CONFIG=true
      ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--include-local-config] [version]

Options:
  --include-local-config  Include local server config files (if present):
                          api.config.php, joyee-bridge.config.php
EOF
      exit 0
      ;;
    *)
      if [[ -n "$VERSION" ]]; then
        echo "Usage: $0 [--include-local-config] [version]" >&2
        exit 1
      fi
      VERSION="$arg"
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  if [[ -f "$VERSION_FILE" ]]; then
    VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
  else
    VERSION="$DEFAULT_VERSION"
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

# Ensure git working tree is clean, but ignore RELEASE_VERSION.
# RELEASE_VERSION is allowed to be dirty because it is the release marker itself.
DIRTY_FILTER='^[ MARC?DU]{1,2} RELEASE_VERSION$'
if [[ "$INCLUDE_LOCAL_CONFIG" == true ]]; then
  DIRTY_FILTER='^[ MARC?DU]{1,2} (RELEASE_VERSION|api\.config\.php|joyee-bridge\.config\.php)$'
fi
DIRTY_STATUS="$(git status --porcelain | grep -vE "$DIRTY_FILTER" || true)"
if [[ -n "$DIRTY_STATUS" ]]; then
  echo "Error: git working tree is not clean. Commit or stash your changes before releasing." >&2
  echo "$DIRTY_STATUS" >&2
  exit 1
fi

# Persist requested/default version after validation.
echo "$VERSION" > "$VERSION_FILE"

OUT_DIR="$ROOT_DIR/releases"
OUT_FILE="$OUT_DIR/tinyfilemanager-${VERSION}.zip"
TMP_LIST="$(mktemp)"
trap 'rm -f "$TMP_LIST"' EXIT

mkdir -p "$OUT_DIR"

# Package tracked files to avoid accidental local artifacts.
# Never include previously generated release archives.
# Exclude development-only directories from production release bundles.
# Private deployment config files are intentionally included in private release builds when present.
git -C "$ROOT_DIR" ls-files | grep -Ev '^(releases/|\.github/|tests/|docs/archive/|DOCS_AUDIT\.md$|ROADMAP_DREMONT\.md$|SMOKE_TEST_2\.9\.19\.md$|\.gitignore$|\.gitattributes$)|\.(zip|tar|tgz|gz|rar|7z)$' > "$TMP_LIST"

for local_config in api.config.php joyee-bridge.config.php; do
  if [[ -f "$ROOT_DIR/$local_config" ]]; then
    grep -qxF "$local_config" "$TMP_LIST" || echo "$local_config" >> "$TMP_LIST"
  fi
done

if [[ ! -s "$TMP_LIST" ]]; then
  echo "Error: no tracked files found to package." >&2
  exit 1
fi

# PHP lint all PHP files before packaging
while IFS= read -r file; do
  if [[ "$file" == *.php ]]; then
    php -l "$ROOT_DIR/$file" >/dev/null
  fi
done < "$TMP_LIST"

rm -f "$OUT_FILE"
zip -q -9 "$OUT_FILE" -@ < "$TMP_LIST"

echo "Release created: $OUT_FILE"
