#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://127.0.0.1:8080}"

body="$(curl -fsS "$base_url/")"
grep -qi "Správca súborov\|Tiny File Manager" <<<"$body"

echo "Smoke tests passed for $base_url"