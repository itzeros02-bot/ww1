#!/usr/bin/env bash
# pg-mcp test runner — lint, unit, security, and (optionally) integration tests.
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-full}"

if command -v uv >/dev/null 2>&1; then
    PYTEST=(uv run pytest)
    RUFF=(uv run ruff)
elif [ -x ".venv/bin/python" ]; then
    PYTEST=(.venv/bin/python -m pytest)
    RUFF=(.venv/bin/python -m ruff)
else
    echo "[ERROR] Neither uv nor .venv found. Run: uv sync --extra dev" >&2
    exit 1
fi

echo "[1/3] Lint..."
"${RUFF[@]}" check src tests

echo "[2/3] Unit + security tests..."
"${PYTEST[@]}" tests/unit tests/security -q

if [ "$MODE" != "quick" ]; then
    echo "[3/3] Integration tests (real PostgreSQL; auto-skips if unreachable)..."
    "${PYTEST[@]}" tests/integration -q
fi

echo ""
echo "[OK] All checks passed."
