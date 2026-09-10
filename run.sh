#!/usr/bin/env bash
# Run the EyeGuard capture-and-detect loop in the foreground (dev / one-shot).
# For the always-on menu-bar agent use ./install_agent.sh instead.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "No .venv found. Run ./setup.sh first." >&2
  exit 1
fi
source .venv/bin/activate
exec python -m eyeguard.main "$@"
