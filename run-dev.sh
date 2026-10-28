#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
VITE="$ROOT_DIR/frontend/node_modules/.bin/vite"

if [[ ! -x "$PYTHON" ]]; then
  printf 'Missing Python environment: %s\n' "$PYTHON" >&2
  printf 'Create it with: python3 -m venv .venv\n' >&2
  exit 1
fi

if [[ ! -x "$VITE" ]]; then
  printf 'Missing frontend dependencies: %s\n' "$VITE" >&2
  printf 'Install them with: (cd frontend && npm install)\n' >&2
  exit 1
fi

backend_pid=
frontend_pid=

cleanup() {
  trap - EXIT INT TERM
  [[ -n "$backend_pid" ]] && kill "$backend_pid" 2>/dev/null || true
  [[ -n "$frontend_pid" ]] && kill "$frontend_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"
"$PYTHON" -m uvicorn app.main:app --reload &
backend_pid=$!

(cd "$ROOT_DIR/frontend" && npm run dev -- --host 127.0.0.1) &
frontend_pid=$!

printf 'Backend:  http://127.0.0.1:8000\n'
printf 'Frontend: http://127.0.0.1:5173\n'
printf 'Press Ctrl+C to stop both.\n'

wait -n "$backend_pid" "$frontend_pid"
