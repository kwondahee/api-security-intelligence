import json
import os

LOG_FILE = "intelligence/log/agents.jsonl"
GROUND_TRUTH_FILE = "ground_truth.json"
OUTPUT_FILE = "orchestrator_eval_results.json"


def load_ground_truth():
    with open(GROUND_TRUTH_FILE, "r") as f:
        return json.load(f)


def load_agent_logs():
    """
    Expected format of each line in agents.jsonl:
    {
        "endpoint": "...",
        "agent": "AuthAgent",
        "trace_id": "...",
        "extra": {...}
    }
    """
    logs = []
    if not os.path.exists(LOG_FILE):
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return logs

    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                logs.append(json.loads(line))
            except Exception:
                pass  # ignore malformed lines

    return logs


def normalize_endpoint(url: str):
    """Removes query order issues or trailing slashes."""
    return url.rstrip("/").lower()


def update_predictions():
    print("=======================================================")
    print("   🔍 Updating Predictions using Orchestrator Logs")
    print("=======================================================\n")

    gt = load_ground_truth()
    logs = load_agent_logs()

    if not logs:
        print("[WARNING] No logs found. Nothing to update.")
        return

    # Create lookup: endpoint -> last prediction
    predictions = {}

    for entry in logs:
        endpoint = entry.get("endpoint")
        agent = entry.get("agent")

        if not endpoint or not agent:
            continue

        endpoint_norm = normalize_endpoint(endpoint)
        predictions[endpoint_norm] = agent

    updated = 0

    # Fill preds into ground truth
    for item in gt:
        ep = normalize_endpoint(item["endpoint"])

        if ep in predictions:
            item["pred"] = predictions[ep]
            updated += 1

    # Save new file
    with open(OUTPUT_FILE, "w") as f:
        json.dump(gt, f, indent=4)

    print(f"[OK] Updated {updated} predictions.")
    print(f"[OK] Saved results to {OUTPUT_FILE}")
    print(f"[OK] Now run: python3 evaluate.py --file {OUTPUT_FILE}")


if __name__ == "__main__":
    update_predictions()
