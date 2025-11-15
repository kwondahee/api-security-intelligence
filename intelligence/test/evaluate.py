import json
import argparse
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)
import numpy as np
import os

# ---------------------------------------------------------------
#  Helper Functions
# ---------------------------------------------------------------

def load_data(path):
    """Load evaluation results from JSON file."""
    with open(path, "r") as f:
        return json.load(f)


def extract_labels(data):
    """Extract true and predicted labels from JSON."""
    true_labels = [item["true"] for item in data]
    pred_labels = [item.get("pred", "UNKNOWN") for item in data]
    return true_labels, pred_labels


def compute_metrics(true_labels, pred_labels):
    """Compute accuracy, precision, recall, F1."""
    accuracy = accuracy_score(true_labels, pred_labels)

    precision, recall, f1, support = precision_recall_fscore_support(
        true_labels,
        pred_labels,
        labels=list(sorted(set(true_labels))),
        zero_division=0
    )

    report = classification_report(
        true_labels, pred_labels, digits=4, zero_division=0
    )

    labels = list(sorted(set(true_labels)))
    cm = confusion_matrix(true_labels, pred_labels, labels=labels)

    return accuracy, precision, recall, f1, support, report, labels, cm


def print_metrics(accuracy, precision, recall, f1, support, labels, report, cm):
    print("\n====================================================")
    print("                📊 Evaluation Metrics                ")
    print("====================================================")
    print(f"Accuracy: {accuracy:.4f}\n")

    print("Per-Class Metrics:")
    print("----------------------------------------------------")
    print("{:<15} {:<10} {:<10} {:<10} {:<10}".format(
        "Agent", "Precision", "Recall", "F1", "Support"
    ))
    for i, label in enumerate(labels):
        print("{:<15} {:<10.4f} {:<10.4f} {:<10.4f} {:<10d}".format(
            label, precision[i], recall[i], f1[i], support[i]
        ))

    print("\nFull Classification Report:")
    print("----------------------------------------------------")
    print(report)

    print("\nConfusion Matrix:")
    print("----------------------------------------------------")
    print_matrix(labels, cm)


def print_matrix(labels, cm):
    header = "Predicted → " + "  ".join(f"{l:>12}" for l in labels)
    print(header)
    print("-" * len(header))

    for i, row in enumerate(cm):
        row_str = "  ".join(f"{n:>12}" for n in row)
        print(f"True {labels[i]:<8} {row_str}")


# ---------------------------------------------------------------
#  Save Metrics → test/metrics/metrics_XXX.json
# ---------------------------------------------------------------

def get_output_metrics_path(eval_file_path: str) -> str:
    """
    If eval file = evaluation/eval_003.json
    output becomes = test/metrics/metrics_003.json
    """
    os.makedirs("test/metrics", exist_ok=True)

    base = os.path.basename(eval_file_path)         # eval_003.json
    num = base.replace("eval_", "").replace(".json", "")
    filename = f"metrics_{num}.json"
    return os.path.join("test/metrics", filename)


def save_results(path, accuracy, precision, recall, f1, support, labels, cm):
    """Save results to JSON file."""
    output = {
        "accuracy": accuracy,
        "labels": labels,
        "per_class": [
            {
                "label": labels[i],
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i])
            }
            for i in range(len(labels))
        ],
        "confusion_matrix": cm.tolist()
    }

    with open(path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"\n[OK] Saved metrics -> {path}")


# ---------------------------------------------------------------
#  Main Entry
# ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file",
        type=str,
        required=True,
        help="Path to evaluation/eval_XXX.json from update_pred"
    )
    args = parser.parse_args()

    # Load Data
    data = load_data(args.file)
    true_labels, pred_labels = extract_labels(data)

    # Compute Metrics
    accuracy, precision, recall, f1, support, report, labels, cm = compute_metrics(true_labels, pred_labels)

    # Print Results
    print_metrics(accuracy, precision, recall, f1, support, labels, report, cm)

    # Save Output
    out_path = get_output_metrics_path(args.file)
    save_results(out_path, accuracy, precision, recall, f1, support, labels, cm)


if __name__ == "__main__":
    main()
