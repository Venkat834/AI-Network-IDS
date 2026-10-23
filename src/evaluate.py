
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
FEATURES_FILE = BASE_DIR / "data" / "traffic_features.csv"
ALERTS_FILE = BASE_DIR / "reports" / "alerts.csv"

# Ground-truth labels for this synthetic dataset only.
# 0 = normal, 1 = simulated suspicious scenario.
GROUND_TRUTH = {
    "192.0.2.10": 0,
    "198.51.100.20": 1,
    "198.51.100.30": 1,
    "198.51.100.40": 1,
}


def main():
    features = pd.read_csv(FEATURES_FILE)
    alerts = pd.read_csv(ALERTS_FILE)

    features["actual"] = features["src_ip"].map(GROUND_TRUTH)

    if features["actual"].isna().any():
        raise ValueError("Some source IPs lack ground-truth labels.")

    alerted_sources = set(alerts["src_ip"]) if not alerts.empty else set()
    features["predicted"] = features["src_ip"].isin(alerted_sources).astype(int)

    actual = features["actual"].astype(int)
    predicted = features["predicted"].astype(int)

    tp = int(((actual == 1) & (predicted == 1)).sum())
    tn = int(((actual == 0) & (predicted == 0)).sum())
    fp = int(((actual == 0) & (predicted == 1)).sum())
    fn = int(((actual == 1) & (predicted == 0)).sum())

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    accuracy = (tp + tn) / len(features) if len(features) else 0

    print("=== Synthetic Dataset Evaluation ===")
    print(f"True positives (TP):  {tp}")
    print(f"False positives (FP): {fp}")
    print(f"True negatives (TN):  {tn}")
    print(f"False negatives (FN): {fn}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"Accuracy:  {accuracy:.2%}")
    print("\nPer-source results:")
    print(features[["src_ip", "actual", "predicted"]].to_string(index=False))

    print(
        "\nCaution: these metrics use four hand-designed synthetic "
        "source-IP scenarios. They are not representative of real "
        "network performance."
    )


if __name__ == "__main__":
    main()
