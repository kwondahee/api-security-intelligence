#!/usr/bin/env python3
"""
Evaluation script for API Security Orchestrator predictions.
Compares ground truth vs predicted agent routing.
"""

import json
import argparse
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

def load_dataset(path):
    """Load JSON evaluation file with fields: endpoint, gt, pred."""
    with open(path, "r") as f:
        return json.load(f)


def evaluate_predictions(data):
    """
    Compute and print evaluation metrics.
    Expected format of each record:
    {
        "endpoint": "...",
        "gt": "AuthAgent",
        "pred": "InputAgent"
    }
    """
    y_true = [item["gt"] for item in data]
    y_pred = [item.get("pred", None) for item in data]

    print("=====================================================")
    print("                📊 Evaluation Report")
    print("=====================================================")

    # --- Accuracy ---
    accuracy = accuracy_score(y_true, y_pred)
    print(f"Accuracy: {accuracy:.4f}")

    # --- Precision, Recall, F1 ---
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    # --- Confusion Matrix ---
    labels = sorted(list(set(y_true + y_pred)))
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    print("\nConfusion Matrix (Rows = True, Cols = Pred):")
    print("Labels:", labels)
    for row in cm:
        print(row)

    # --- Full Classification Report ---
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, zero_division=0))


def main():
    parser = argparse.ArgumentParser(description="Evaluate routing predictions.")
    parser.add_argument("--file", default="orchestrator_eval_results.json",
                        help="Path to evaluation JSON file")

    args = parser.parse_args()

    data = load_dataset(args.file)
    evaluate_predictions(data)


if __name__ == "__main__":
    main()
