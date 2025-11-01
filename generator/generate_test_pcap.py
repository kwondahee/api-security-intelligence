#!/usr/bin/env python3
import json
from pathlib import Path

SAMPLE = [
    {"method": "GET",  "url": "http://localhost:8080/api/v1/public/status"},
    {"method": "GET",  "url": "http://localhost:8080/rest/users", "headers": {"Authorization": "Bearer user:1"}},
    {"method": "GET",  "url": "http://localhost:8080/rest/user/24"},
    {"method": "GET",  "url": "http://localhost:8080/search", "params": {"q": "' OR 1=1 --"}},
]

if __name__ == "__main__":
    Path("pcap_replay.jsonl").write_text("\n".join(json.dumps(x) for x in SAMPLE), encoding="utf-8")
    print("Wrote pcap_replay.jsonl (toy log). Use dissector to ingest.")
