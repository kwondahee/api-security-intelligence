import json
import os
from urllib.parse import urlparse
from datetime import datetime

GROUND_TRUTH_FILE = "test/ground_truth.json"
EVAL_FOLDER = "test/evaluation"


def get_latest_log():
    """Pick the newest agents_XXX.jsonl file automatically."""
    if not os.path.exists("log"):
        return None

    logs = [f for f in os.listdir("log") if f.startswith("agents_") and f.endswith(".jsonl")]
    if not logs:
        return None

    logs_sorted = sorted(logs)
    return os.path.join("log", logs_sorted[-1])


def get_next_eval_filename():
    """Increment eval file numbers."""
    os.makedirs(EVAL_FOLDER, exist_ok=True)

    existing = [
        f for f in os.listdir(EVAL_FOLDER)
        if f.startswith("eval_") and f.endswith(".json")
    ]

    if not existing:
        next_num = 1
    else:
        nums = []
        for f in existing:
            num = f.replace("eval_", "").replace(".json", "")
            if num.isdigit():
                nums.append(int(num))
        next_num = max(nums) + 1 if nums else 1

    return os.path.join(EVAL_FOLDER, f"eval_{next_num:03d}.json")


def load_ground_truth():
    with open(GROUND_TRUTH_FILE, "r") as f:
        return json.load(f)


def load_agent_logs(log_path):
    logs = []
    if not log_path or not os.path.exists(log_path):
        print(f"[ERROR] Log file not found: {log_path}")
        return logs

    with open(log_path, "r") as f:
        for line in f:
            try: logs.append(json.loads(line))
            except: pass

    return logs


def normalize_path(url: str):
    parsed = urlparse(url)
    return parsed.path.rstrip("/").lower()


def update_predictions():
    print("=======================================================")
    print("   🔍 Updating Predictions using Latest LOG")
    print("=======================================================\n")

    log_file = get_latest_log()
    print(f"[INFO] Using log file: {log_file}")

    gt = load_ground_truth()
    logs = load_agent_logs(log_file)

    predictions = {}
    for entry in logs:
        ep = entry.get("endpoint")
        agent = entry.get("agent")
        if not ep or not agent:
            continue
        predictions[normalize_path(ep)] = agent

    updated = 0
    for item in gt:
        gt_path = normalize_path(item["endpoint"])
        item["pred"] = predictions.get(gt_path, "UNKNOWN")
        if gt_path in predictions:
            updated += 1

    eval_output = get_next_eval_filename()
    with open(eval_output, "w") as f:
        json.dump(gt, f, indent=4)

    print(f"[OK] Updated {updated} predictions")
    print(f"[OK] Saved -> {eval_output}")


if __name__ == "__main__":
    update_predictions()
