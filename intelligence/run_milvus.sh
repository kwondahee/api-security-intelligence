#!/bin/bash
# run_milvus.sh — starts Milvus via Docker Compose safely

set -e  # fail on errors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================="
echo "[MILVUS] Starting Milvus via Docker Compose"
echo "Directory: $SCRIPT_DIR"
echo "====================================================="

# ---------------------------------------------------------
# [1] Setup Python venv
# ---------------------------------------------------------
if [ ! -d "venv" ]; then
  echo "[MILVUS] Creating Python virtual environment..."
  python3 -m venv venv
fi

echo "[MILVUS] Activating venv..."
source venv/bin/activate


# --- [2] Ensure Docker is running ---
if ! systemctl is-active --quiet docker; then
  echo "[MILVUS] Docker is not running → starting Docker..."
  systemctl start docker
fi

echo "[MILVUS] Docker is running ✔"


# --- [3] Ensure docker-compose.yml exists ---
if [ ! -f "docker-compose.yml" ]; then
  echo "[ERROR] docker-compose.yml not found in: $SCRIPT_DIR"
  exit 1
fi

# --- [4] Start Milvus with Docker Compose ---
echo "[MILVUS] Launching Milvus containers..."
docker compose up -d


# --- [5] Wait for Milvus to become healthy ---
echo "[MILVUS] Waiting for Milvus to be ready..."

RETRIES=20
SLEEP=3

for i in $(seq 1 $RETRIES); do
  if curl -s http://localhost:19530/api/v1/healthy | grep -q "true"; then
    echo "[MILVUS] Milvus is healthy ✔"
    exit 0
  fi

  echo "[MILVUS] Milvus not ready yet ($i/$RETRIES)... retrying in $SLEEP seconds"
  sleep $SLEEP
done

echo "[ERROR] Milvus did not become healthy in time."
exit 1
