#!/usr/bin/env bash
# aurum-verify-starter — one-shot local setup.
# Creates a virtualenv, installs dependencies, and bootstraps .env.
# Safe to re-run: it never overwrites an existing .env.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: $PYTHON not found. Install Python 3.10+ and re-run." >&2
  exit 1
fi

VENV_DIR="${VENV_DIR:-.venv}"
if [ ! -d "$VENV_DIR" ]; then
  echo ">> creating virtualenv in $VENV_DIR"
  "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo ">> upgrading pip"
python -m pip install --upgrade pip >/dev/null

echo ">> installing dependencies"
python -m pip install -r requirements.txt

if [ ! -f .env ]; then
  echo ">> writing .env from .env.example"
  cp .env.example .env
  echo ">> EDIT .env NOW: set VERIFY_PAY_TO to your receive-only address."
else
  echo ">> .env already exists, leaving it untouched"
fi

cat <<'EOF'

Setup complete.

  1. Edit .env and set VERIFY_PAY_TO (your receive-only address).
  2. Run test mode (no chain, no wallet):
       uvicorn service.app:app --port 8000
  3. Smoke-test the gate:
       curl -si -X POST localhost:8000/v1/verify/claims \
         -H 'content-type: application/json' \
         -d '{"claims":["The sky is blue."],"sources":[{"url":"https://example.com"}]}'
     Expect HTTP 402 with a PAYMENT-REQUIRED header.

See README.md for the full x402 integration flow.
EOF
