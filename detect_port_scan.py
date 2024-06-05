from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

ip_counts = defaultdict(int)
last_checked = defaultdict(lambda: time.time())

def detect_port_scan(packet):
    # Check if the packet contains TCP and IP layers before processing
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags & 2:  # TCP SYN flag is 2
            src_ip = packet[IP].src
            current_time = time.time()
            if current_time - last_checked[src_ip] > 60:
                ip_counts[src_ip] = 0
                last_checked[src_ip] = current_time
            ip_counts[src_ip] += 1
            if ip_counts[src_ip] > 100:
                print(f"Potential port scan detected from {src_ip}")
                ip_counts[src_ip] = 0

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):  # Ensure packet has both IP and TCP layers
        detect_port_scan(packet)
        print(f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}")

sniff(prn=packet_callback, filter="tcp", store=False)
