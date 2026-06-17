#!/usr/bin/env bash
set -euo pipefail

# Build a versioned release ZIP from tracked repository files.
# Usage:
#   ./release.sh                          # uses version from RELEASE_VERSION
#   ./release.sh 1.2.0                    # uses provided version
#   ./release.sh patch|minor|major|mini   # increments current RELEASE_VERSION
#   ./release.sh --include-local-config [version|patch|minor|major|mini]
#   ./release.sh patch --auto-commit
#   ./release.sh patch --auto-commit --auto-push

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VERSION_FILE="RELEASE_VERSION"
DEFAULT_VERSION="1.1"
INCLUDE_LOCAL_CONFIG=false
AUTO_COMMIT=false
AUTO_PUSH=false
COMMIT_MESSAGE=""

VERSION=""
BUMP_MODE=""
for arg in "$@"; do
  case "$arg" in
    --include-local-config)
      INCLUDE_LOCAL_CONFIG=true
      ;;
    --auto-commit)
      AUTO_COMMIT=true
      ;;
    --auto-push)
      AUTO_PUSH=true
      ;;
    --commit-message=*)
      COMMIT_MESSAGE="${arg#*=}"
      ;;
    patch|minor|major|mini)
      if [[ -n "$VERSION" || -n "$BUMP_MODE" ]]; then
        echo "Usage: $0 [--include-local-config] [--auto-commit] [--auto-push] [--commit-message=...] [version|patch|minor|major|mini]" >&2
        exit 1
      fi
      BUMP_MODE="$arg"
      ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--include-local-config] [--auto-commit] [--auto-push] [--commit-message=...] [version|patch|minor|major|mini]

Options:
  --include-local-config  Include local server config files (if present):
                          api.config.php, joyee-bridge.config.php
  --auto-commit           Automatically commit RELEASE_VERSION and release ZIP
  --auto-push             Push current branch to origin after release
  --commit-message=MSG    Custom commit message for --auto-commit

Version argument:
  version                 Explicit version, e.g. 2.10.5
  patch                   Increment patch segment (x.y.z -> x.y.(z+1))
  minor|mini              Increment minor segment (x.y.z -> x.(y+1).0)
  major                   Increment major segment (x.y.z -> (x+1).0.0)
EOF
      exit 0
      ;;
    *)
      if [[ -n "$VERSION" ]]; then
        echo "Usage: $0 [--include-local-config] [--auto-commit] [--auto-push] [--commit-message=...] [version|patch|minor|major|mini]" >&2
        exit 1
      fi
      VERSION="$arg"
      ;;
  esac
done

if [[ "$AUTO_PUSH" == true && "$AUTO_COMMIT" == false ]]; then
  AUTO_COMMIT=true
fi

if [[ -f "$VERSION_FILE" ]]; then
  CURRENT_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
else
  CURRENT_VERSION="$DEFAULT_VERSION"
fi

if [[ -z "$CURRENT_VERSION" ]]; then
  CURRENT_VERSION="$DEFAULT_VERSION"
fi

if [[ -n "$BUMP_MODE" ]]; then
  if ! [[ "$CURRENT_VERSION" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]]; then
    echo "Error: current version '$CURRENT_VERSION' is not numeric and cannot be bumped automatically." >&2
    echo "Use explicit version, e.g. ./release.sh 2.10.6" >&2
    exit 1
  fi

  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[4]:-0}"

  case "$BUMP_MODE" in
    patch)
      patch=$((patch + 1))
      ;;
    minor|mini)
      minor=$((minor + 1))
      patch=0
      ;;
    major)
      major=$((major + 1))
      minor=0
      patch=0
      ;;
  esac

  VERSION="${major}.${minor}.${patch}"
elif [[ -z "$VERSION" ]]; then
  VERSION="$CURRENT_VERSION"
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
# Runtime state under .fm_usercfg is server-local and should not ship in release zips.
# Private deployment config files are intentionally included in private release builds when present.
git -C "$ROOT_DIR" ls-files \
  | grep -Ev '^(releases/|\.github/|tests/|docs/archive/|\.fm_usercfg/|DOCS_AUDIT\.md$|ROADMAP_DREMONT\.md$|SMOKE_TEST_2\.9\.19\.md$|\.gitignore$|\.gitattributes$)|\.(zip|tar|tgz|gz|rar|7z)$' \
  > "$TMP_LIST"

# Keep hardening rules from dropping a tracked .htaccess template for .fm_usercfg.
if git -C "$ROOT_DIR" ls-files --error-unmatch .fm_usercfg/.htaccess >/dev/null 2>&1; then
  grep -qxF ".fm_usercfg/.htaccess" "$TMP_LIST" || echo ".fm_usercfg/.htaccess" >> "$TMP_LIST"
fi

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

if [[ "$AUTO_COMMIT" == true ]]; then
  if [[ -z "$COMMIT_MESSAGE" ]]; then
    COMMIT_MESSAGE="Release ${VERSION}"
  fi

  git add "$VERSION_FILE"
  git add -f "$OUT_FILE"

  if git diff --cached --quiet; then
    echo "Auto-commit skipped: no staged changes."
  else
    git commit -m "$COMMIT_MESSAGE"
    echo "Auto-commit created: $COMMIT_MESSAGE"
  fi
fi

if [[ "$AUTO_PUSH" == true ]]; then
  CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "$CURRENT_BRANCH" == "HEAD" || -z "$CURRENT_BRANCH" ]]; then
    echo "Error: cannot auto-push from detached HEAD." >&2
    exit 1
  fi

  git push origin "$CURRENT_BRANCH"
  echo "Auto-push completed: origin/$CURRENT_BRANCH"
fi
