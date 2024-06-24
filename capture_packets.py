from scapy.all import sniff, TCP, IP
from collections import defaultdict

ip_counts = defaultdict(int)

def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN flag for TCP
        ip_counts[packet[IP].src] += 1
        if ip_counts[packet[IP].src] > 10:  # Threshold value
            print(f"Port scan detected from {packet[IP].src}")

def packet_callback(packet):
    detect_port_scan(packet)
    if packet.haslayer(TCP):
        print(f"TCP Packet: {packet[IP].src} -> {packet[IP].dst}")
    elif packet.haslayer(UDP):
        print(f"UDP Packet: {packet[IP].src} -> {packet[IP].dst}")

sniff(prn=packet_callback, count=100)
