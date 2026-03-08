#!/bin/bash
# AutoRecon Launcher
set -e

echo "╔═══════════════════════════════════════╗"
echo "║     AutoRecon v2.0 — Starting...      ║"
echo "╚═══════════════════════════════════════╝"

cd "$(dirname "$0")"

# Install Python deps
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt -q 2>/dev/null || pip3 install -r requirements.txt -q

# Create data directory
mkdir -p ~/.autorecon/output

# Start FastAPI backend
echo "[*] Starting FastAPI backend on :8000..."
uvicorn main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
sleep 2

# Open browser
echo "[*] Opening browser..."
if command -v xdg-open &>/dev/null; then
    xdg-open http://localhost:5173 2>/dev/null &
elif command -v open &>/dev/null; then
    open http://localhost:5173 &
fi

# Start frontend dev server
echo "[*] Starting frontend on :5173..."
cd ../
npm run dev

# Cleanup on exit
trap "kill $BACKEND_PID 2>/dev/null" EXIT
