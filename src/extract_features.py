
from collections import defaultdict
from pathlib import Path

import pandas as pd
from scapy.all import IP, TCP, UDP, rdpcap

PCAP_FILE = Path("data") / "sample_traffic.pcap"
OUTPUT_FILE = Path("data") / "traffic_features.csv"


def extract_features(pcap_file):
    packets = rdpcap(str(pcap_file))
    flows = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "start_time": None,
        "end_time": None,
        "dst_ports": set(),
        "protocols": set(),
        "tcp_syn": 0,
    })

    for packet in packets:
        if IP not in packet:
            continue

        ip = packet[IP]
        src_ip = ip.src
        key = src_ip
        flow = flows[key]

        timestamp = float(packet.time)
        flow["packets"] += 1
        flow["bytes"] += len(packet)
        flow["start_time"] = (
            timestamp if flow["start_time"] is None
            else min(flow["start_time"], timestamp)
        )
        flow["end_time"] = (
            timestamp if flow["end_time"] is None
            else max(flow["end_time"], timestamp)
        )

        if TCP in packet:
            flow["protocols"].add("TCP")
            flow["dst_ports"].add(int(packet[TCP].dport))
            if packet[TCP].flags & 0x02:
                flow["tcp_syn"] += 1
        elif UDP in packet:
            flow["protocols"].add("UDP")
        else:
            flow["protocols"].add("Other")

    rows = []
    for src_ip, flow in flows.items():
        duration = max(
            flow["end_time"] - flow["start_time"], 0.001
        )
        rows.append({
            "src_ip": src_ip,
            "packets": flow["packets"],
            "bytes": flow["bytes"],
            "duration": round(duration, 6),
            "packet_rate": round(flow["packets"] / duration, 2),
            "unique_dst_ports": len(flow["dst_ports"]),
            "protocols": ",".join(sorted(flow["protocols"])),
            "tcp_syn_packets": flow["tcp_syn"],
        })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    if not PCAP_FILE.exists():
        raise FileNotFoundError(f"Capture not found: {PCAP_FILE}")

    df = extract_features(PCAP_FILE)
    df.to_csv(OUTPUT_FILE, index=False)

    print("Feature extraction complete.")
    print(f"PCAP packets: {sum(df['packets'])}")
    print(f"Source IPs found: {len(df)}")
    print(f"CSV saved to: {OUTPUT_FILE}")
    print()
    print(df.to_string(index=False))
