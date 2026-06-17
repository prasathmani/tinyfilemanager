#!/usr/bin/env bash
set -euo pipefail

# Run a clean preview of origin/master in a separate worktree.
# Usage:
#   ./scripts/run-master-preview.sh
#   ./scripts/run-master-preview.sh --port 8090
#   ./scripts/run-master-preview.sh --no-open

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKTREE_DIR="${ROOT_DIR}/../tinyfilemanager-master"
PORT="8080"
OPEN_BROWSER="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --port" >&2
        exit 1
      fi
      PORT="$2"
      shift 2
      ;;
    --no-open)
      OPEN_BROWSER="0"
      shift
      ;;
    -h|--help)
      cat <<EOF
Usage: ./scripts/run-master-preview.sh [--port PORT] [--no-open]

Options:
  --port PORT  Port for PHP server (default: 8080)
  --no-open    Do not open browser automatically
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v php >/dev/null 2>&1; then
  echo "php is not installed or not in PATH." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed or not in PATH." >&2
  exit 1
fi

echo "[1/4] Fetching latest origin/master..."
git -C "$ROOT_DIR" fetch origin

if [[ ! -d "$WORKTREE_DIR/.git" ]]; then
  echo "[2/4] Creating clean worktree at: $WORKTREE_DIR"
  git -C "$ROOT_DIR" worktree add "$WORKTREE_DIR" origin/master
else
  echo "[2/4] Reusing existing worktree: $WORKTREE_DIR"
  STATUS="$(git -C "$WORKTREE_DIR" status --porcelain)"
  if [[ -n "$STATUS" ]]; then
    echo "Worktree has local changes. Please clean it first:" >&2
    echo "$STATUS" >&2
    exit 1
  fi
  git -C "$WORKTREE_DIR" fetch origin
  git -C "$WORKTREE_DIR" checkout --detach origin/master
fi

URL="http://localhost:${PORT}"

echo "[3/4] Starting PHP server from clean master..."
echo "      Root: $WORKTREE_DIR"
echo "      URL : $URL"

if [[ "$OPEN_BROWSER" == "1" ]]; then
  if [[ -n "${BROWSER:-}" ]]; then
    echo "[4/4] Opening browser via \$BROWSER"
    "$BROWSER" "$URL" >/dev/null 2>&1 &
  else
    echo "[4/4] \$BROWSER is not set, skipping auto-open."
  fi
else
  echo "[4/4] Browser auto-open disabled (--no-open)."
fi

cd "$WORKTREE_DIR"
exec php -S 0.0.0.0:"$PORT" -t .
