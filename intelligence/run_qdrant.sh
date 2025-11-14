#!/bin/bash
# run_qdrant.sh — starts Qdrant and waits until healthz = 200

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================="
echo "[QDRANT] Starting Qdrant Vector DB"
echo "Directory: $SCRIPT_DIR"
echo "====================================================="

# --- Ensure Docker is running ---
if ! systemctl is-active --quiet docker; then
  echo "[QDRANT] Docker not running — starting..."
  systemctl start docker
fi

echo "[QDRANT] Docker is running ✔"

# --- Start Qdrant ---
docker compose up -d

echo "[QDRANT] Waiting for Qdrant to be healthy..."

# --- Correct health check: expect HTTP 200 ---
for i in {1..20}; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6333/healthz || true)
  BODY=$(curl -s http://localhost:6333/healthz || true)

  echo "Status: $STATUS Body: $BODY"

  if [ "$STATUS" = "200" ]; then
    echo "[QDRANT] Qdrant is healthy ✔"
    exit 0
  fi

  echo "[QDRANT] Not ready ($i/20), retrying..."
  sleep 2
done

echo "[ERROR] Qdrant did not become healthy in time."
exit 1
