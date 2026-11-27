#!/usr/bin/env bash
# Scanner sidecar entrypoint. Default CMD keeps the container alive for docker exec.
set -euo pipefail

if [[ "${1:-}" == "wardline" ]]; then
  shift
  exec wardline "$@"
fi

exec "$@"
