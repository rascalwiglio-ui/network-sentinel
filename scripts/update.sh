#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Update cancelled: repository has uncommitted changes." >&2
  echo "Commit them first, or run: git stash -u" >&2
  exit 2
fi

git fetch origin --tags
git pull --ff-only origin main

if [[ ! -x .venv/bin/python ]]; then
  ./scripts/bootstrap.sh
else
  .venv/bin/python -m pip install -r requirements.txt
fi

echo "Update complete."
