
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent.parent
FEATURES_FILE = BASE_DIR / "data" / "traffic_features.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "ml_anomalies.csv"

FEATURE_COLUMNS = [
    "packets",
    "bytes",
    "duration",
    "packet_rate",
    "unique_dst_ports",
    "tcp_syn_packets",
]


def main():
    if not FEATURES_FILE.exists():
        raise FileNotFoundError(
            "Feature CSV missing. Run src\\extract_features.py first."
        )

    df = pd.read_csv(FEATURES_FILE)

    if len(df) < 4:
        raise ValueError(
            "At least four source-IP records are needed for this demo."
        )

    X = df[FEATURE_COLUMNS].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.25,
        random_state=42,
    )
    model.fit(X_scaled)

    df["ml_prediction"] = model.predict(X_scaled)
    df["anomaly_score"] = model.decision_function(X_scaled)
    df["ml_result"] = df["ml_prediction"].map({
        1: "Typical",
        -1: "Anomaly",
    })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print("=== Machine-Learning Anomaly Detection ===")
    print("Algorithm: Isolation Forest")
    print(f"Source records analyzed: {len(df)}")
    print(df[[
        "src_ip", "ml_result", "anomaly_score"
    ]].to_string(index=False))
    print(f"\nResults saved to: {OUTPUT_FILE}")
    print(
        "\nNote: This is a small synthetic demonstration. "
        "An anomaly is not necessarily an attack."
    )


if __name__ == "__main__":
    main()
