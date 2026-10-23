
from pathlib import Path
import pandas as pd

DATA_FILE = Path("data") / "traffic_features.csv"
ALERT_FILE = Path("reports") / "alerts.csv"


def detect_intrusions(df):
    alerts = []

    for _, row in df.iterrows():
        src = row["src_ip"]
        packets = int(row["packets"])
        rate = float(row["packet_rate"])
        unique_ports = int(row["unique_dst_ports"])
        syn_packets = int(row["tcp_syn_packets"])

        # Rule 1: Contact with many destination ports.
        if unique_ports >= 10:
            alerts.append({
                "src_ip": src,
                "alert": "Possible Port Scan",
                "severity": "High",
                "confidence": "High",
                "reason": (
                    f"Source contacted {unique_ports} "
                    "distinct destination ports."
                ),
            })

        # Rule 2: High packet rate.
        if packets >= 50 and rate >= 500:
            alerts.append({
                "src_ip": src,
                "alert": "Possible DoS/Flooding",
                "severity": "High",
                "confidence": "High",
                "reason": (
                    f"{packets} packets observed at "
                    f"{rate:.2f} packets/second."
                ),
            })

        # Rule 3: Repeated TCP SYN attempts to few ports.
        # This does not prove brute-force authentication.
        if (syn_packets >= 12 and unique_ports <= 3 and not (packets >= 50 and rate >= 500)):
            alerts.append({
                "src_ip": src,
                "alert": "Repeated TCP Connection Attempts",
                "severity": "Medium",
                "confidence": "Medium",
                "reason": (
                    f"{syn_packets} TCP SYN packets sent "
                    f"to {unique_ports} distinct destination port(s)."
                ),
            })

    return pd.DataFrame(
        alerts,
        columns=[
            "src_ip", "alert", "severity", "confidence", "reason"
        ],
    )


if __name__ == "__main__":
    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Feature CSV not found: {DATA_FILE}. "
            "Run python src\\extract_features.py first."
        )

    features = pd.read_csv(DATA_FILE)
    alerts = detect_intrusions(features)

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(ALERT_FILE, index=False)

    print("=== PCAP-Based Network Intrusion Detection ===")
    print(f"Source IPs analyzed: {len(features)}")
    print(f"Alerts generated: {len(alerts)}")

    if alerts.empty:
        print("No alerts generated.")
    else:
        print(alerts.to_string(index=False))

    print(f"\nAlerts saved to: {ALERT_FILE}")
