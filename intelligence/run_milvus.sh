#!/bin/bash
# run_milvus.sh — starts Milvus via Docker Compose safely, with Python venv

set -e  # stop on errors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================="
echo "[MILVUS] Starting Milvus via Docker Compose"
echo "Directory: $SCRIPT_DIR"
echo "====================================================="

# ---------------------------------------------------------
# [0] Setup Python venv (optional but recommended)
# ---------------------------------------------------------
if [ ! -d "venv" ]; then
  echo "[MILVUS] Creating Python virtual environment..."
  python3 -m venv venv
fi

echo "[MILVUS] Activating venv..."
source venv/bin/activate

# ---------------------------------------------------------
# [1] Ensure Docker daemon is active
# ---------------------------------------------------------
if ! systemctl is-active --quiet docker; then
  echo "[MILVUS] Docker is not running → starting Docker..."
  systemctl start docker
fi

echo "[MILVUS] Docker is running ✔"

# ---------------------------------------------------------
# [2] Validate docker-compose.yml exists
# ---------------------------------------------------------
if [ ! -f "docker-compose.yml" ]; then
  echo "[ERROR] docker-compose.yml not found in: $SCRIPT_DIR"
  exit 1
fi

# ---------------------------------------------------------
# [3] Start Milvus containers
# ---------------------------------------------------------
echo "[MILVUS] Launching Milvus containers..."
docker compose up -d

# ---------------------------------------------------------
# [4] Wait for Milvus to become healthy
# (your docker-compose exposes health at 9091/healthz)
# ---------------------------------------------------------
echo "[MILVUS] Waiting for Milvus to become healthy..."

RETRIES=40      # ~120 seconds total
SLEEP=3

for i in $(seq 1 $RETRIES); do
  HEALTH=$(curl -s http://localhost:9091/healthz || true)

  # Expected: {"status":"healthy"}
  if echo "$HEALTH" | grep -q '"status":"healthy"'; then
    echo "[MILVUS] Milvus is fully healthy ✔"
    exit 0
  fi

  echo "[MILVUS] Milvus not ready yet ($i/$RETRIES)... retrying in $SLEEP seconds"
  sleep $SLEEP
done

echo "[ERROR] Milvus did not become healthy in time."
exit 1
