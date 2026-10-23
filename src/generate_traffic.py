
from scapy.all import Ether, IP, TCP, wrpcap
from pathlib import Path

# Save the capture in the project's data folder.
OUTPUT = Path("data") / "sample_traffic.pcap"
packets = []

def add_tcp_packet(src, dst, sport, dport, timestamp, flags="S"):
    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
    )
    packet.time = timestamp
    packets.append(packet)

# Scenario 1: normal traffic
for i in range(10):
    add_tcp_packet(
        "192.0.2.10", "192.0.2.100",
        50000 + i, 443, 1000 + i, flags="S"
    )

# Scenario 2: simulated port scan
for i, port in enumerate(range(20, 35)):
    add_tcp_packet(
        "198.51.100.20", "192.0.2.100",
        40000 + i, port, 1010 + i * 0.1, flags="S"
    )

# Scenario 3: simulated high-volume traffic
for i in range(120):
    add_tcp_packet(
        "198.51.100.30", "192.0.2.100",
        45000 + (i % 100), 80, 1020 + i * 0.001, flags="S"
    )

# Scenario 4: repeated connections to an SSH service.
# This is NOT proof of brute-force authentication.
for i in range(15):
    add_tcp_packet(
        "198.51.100.40", "192.0.2.100",
        46000 + i, 22, 1030 + i * 0.2, flags="S"
    )

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(OUTPUT), packets)

print(f"PCAP created: {OUTPUT}")
print(f"Total packets: {len(packets)}")
print("Scenarios: normal, port scan, high-volume traffic, repeated SSH connections")
