#!/usr/bin/env bash
# Run the Surface Check generator test suite. Usage: ./run_tests.sh [pytest args]
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/pytest ]; then python3 -m venv .venv && .venv/bin/pip install -q pytest; fi
exec .venv/bin/pytest -q tests "$@"
