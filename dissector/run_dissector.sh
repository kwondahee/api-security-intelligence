#!/bin/bash
set -euo pipefail

INBOX="/home/ubuntu/pcap_inbox"
DONE="/home/ubuntu/pcap_processed"
SCRIPT="/home/ubuntu/api-security-intelligence/dissector/dissector.py"
PYBIN="/home/ubuntu/api-security-intelligence/dissector/venv/bin/python"

mkdir -p "$INBOX" "$DONE"

for f in "$INBOX"/*.pcap*; do
    [ -e "$f" ] || continue
    echo "Processing $f"
    "$PYBIN" "$SCRIPT" "$f" > "${f}.json"
    mv "$f" "$DONE/"
done