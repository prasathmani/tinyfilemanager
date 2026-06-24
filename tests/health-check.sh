#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://127.0.0.1:8080}"
status_code="$(curl -o /dev/null -s -w '%{http_code}' "$base_url/")"

if [[ "$status_code" != "200" ]]; then
    echo "Health check failed with HTTP $status_code"
    exit 1
fi

echo "Health check passed for $base_url"