
import pandas as pd
from detector import detect_intrusions

# Simulated scan-like activity below the detector threshold.
test_case = pd.DataFrame([{
    "src_ip": "198.51.100.50",
    "packets": 9,
    "bytes": 486,
    "duration": 2.0,
    "packet_rate": 4.5,
    "unique_dst_ports": 9,
    "protocols": "TCP",
    "tcp_syn_packets": 9,
}])

alerts = detect_intrusions(test_case)

print("=== Demo 5: Ambiguous / Potentially Missed Activity ===")
print("Source contacted 9 distinct destination ports.")
print("Port-scan alert threshold: 10 distinct ports.")

if alerts.empty:
    print("Result: No alert generated.")
    print("Limitation: Scan-like activity below the threshold may be missed.")
else:
    print(alerts.to_string(index=False))
