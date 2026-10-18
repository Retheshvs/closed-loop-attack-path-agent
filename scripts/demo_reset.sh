#!/usr/bin/env bash
set -e

echo "=========================================="
echo "  Closed-Loop Attack-Path Agent Demo Reset"
echo "=========================================="

ENDPOINT="http://localhost:8000/reset"

echo "Sending POST request to ${ENDPOINT}..."
RESPONSE=$(curl -s -X POST "${ENDPOINT}" || true)

if [ -n "$RESPONSE" ]; then
    echo "Reset response received."
    echo "${RESPONSE}"
else
    echo "Warning: Could not connect to ${ENDPOINT}."
    echo "Ensure the application is running (e.g. docker compose up or uvicorn)."
fi

echo ""
echo "Opening http://localhost:8000 in your browser..."
if command -v xdg-open > /dev/null; then
    xdg-open "http://localhost:8000"
elif command -v open > /dev/null; then
    open "http://localhost:8000"
else
    echo "Please open http://localhost:8000 manually."
fi
