#!/bin/bash
set -euo pipefail

# Directory where tcpdump writes PCAPs on API VM
PCAP_DIR="/var/lib/tcpdump"

# Dissector VM details
DEST_USER="ubuntu"
DEST_HOST="192.168.218.130"   # <-- change if your dissector-vm IP changes
DEST_DIR="/home/ubuntu/pcap_inbox"

mkdir -p "$PCAP_DIR"

for f in "$PCAP_DIR"/*.pcap*; do
    [ -e "$f" ] || continue

    echo "Sending $f to ${DEST_USER}@${DEST_HOST}:${DEST_DIR}"
    scp -o StrictHostKeyChecking=no "$f" "${DEST_USER}@${DEST_HOST}:${DEST_DIR}/"

    # Only delete if scp succeeded
    if [ $? -eq 0 ]; then
        rm -f "$f"
    else
        echo "Failed to send $f, keeping it for retry" >&2
    fi
done
