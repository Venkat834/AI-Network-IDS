
from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
FEATURES_FILE = BASE_DIR / "data" / "traffic_features.csv"
ALERTS_FILE = BASE_DIR / "reports" / "alerts.csv"
ML_FILE = BASE_DIR / "reports" / "ml_anomalies.csv"

st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Network Intrusion Detection System")
st.caption("PCAP analysis | Rule-based detection + Isolation Forest")

if not FEATURES_FILE.exists():
    st.error("Feature file missing. Run src\\extract_features.py first.")
    st.stop()

if not ALERTS_FILE.exists():
    st.error("Alert file missing. Run src\\detector.py first.")
    st.stop()

features = pd.read_csv(FEATURES_FILE)
alerts = pd.read_csv(ALERTS_FILE)

ml_results = None
if ML_FILE.exists():
    ml_results = pd.read_csv(ML_FILE)

total_sources = features["src_ip"].nunique()
total_packets = int(features["packets"].sum())
alert_count = len(alerts)
high_alerts = int((alerts["severity"] == "High").sum()) if alert_count else 0
anomaly_count = (
    int((ml_results["ml_result"] == "Anomaly").sum())
    if ml_results is not None else 0
)

if ml_results is not None:
    c1, c2, c3, c4, c5 = st.columns(5)
else:
    c1, c2, c3, c4 = st.columns(4)

c1.metric("Source IPs", total_sources)
c2.metric("Packets Analyzed", total_packets)
c3.metric("Rule-Based Alerts", alert_count)
c4.metric("High-Severity Alerts", high_alerts)

if ml_results is not None:
    c5.metric("ML Anomalies", anomaly_count)

st.divider()

st.subheader("Extracted Traffic Features")
st.dataframe(features, use_container_width=True, hide_index=True)

st.subheader("Packets by Source IP")
st.bar_chart(features.set_index("src_ip")[["packets"]])

st.subheader("Rule-Based Detection Alerts")
if alerts.empty:
    st.success("No rule-based alerts generated.")
else:
    severity_filter = st.selectbox(
        "Filter alerts by severity",
        ["All", "High", "Medium", "Low"],
    )
    visible_alerts = alerts
    if severity_filter != "All":
        visible_alerts = alerts[alerts["severity"] == severity_filter]

    st.dataframe(visible_alerts, use_container_width=True, hide_index=True)

st.divider()
st.subheader("Machine-Learning Anomaly Detection")

if ml_results is None:
    st.warning(
        "ML results not found. Run python src\\ml_detector.py first."
    )
else:
    st.dataframe(
        ml_results[["src_ip", "ml_result", "anomaly_score"]],
        use_container_width=True,
        hide_index=True,
    )
    st.caption(
        "Isolation Forest results are exploratory. The model uses only "
        "four synthetic source records; an anomaly is not necessarily an attack."
    )

st.info(
    "Dataset note: this dashboard uses synthetic PCAP traffic. "
    "Rule matches and ML anomalies are indicators, not confirmed attacks. "
    "The current ML model has not been validated on real-world data."
)
