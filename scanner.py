import time
from scapy.all import IP, TCP, send

# 1. Configuration
target_ip = "ADD YOUR IP ADDRESS HERE"  # <--- REPLACE WITH YOUR TARGET IP
ports_to_scan = range(1, 101)  # Scanning first 100 ports
delay_seconds = 0.5  # <--- ADJUST THIS for "Slow" scanning

print(f"[*] Starting SLOW scan on {target_ip}...")

for port in ports_to_scan:
    # Create a SYN packet
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    
    # Send the packet (verbose=False keeps the scanner terminal clean)
    send(packet, verbose=False)
    
    print(f"[+] Scanned Port: {port}")
    
    # 2. The "Slow" Vibe: Pause between every packet
    time.sleep(delay_seconds)

print("[*] Scan Complete.")