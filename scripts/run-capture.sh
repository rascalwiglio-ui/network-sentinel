#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SENTINEL_PACKET_CAPTURE=1
exec .venv/bin/python -m sentinel.app
