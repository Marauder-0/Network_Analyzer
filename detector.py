from collections import defaultdict
import time

WHITELIST = {"8.8.8.8", "8.8.4.4", "192.168.1.1"}

# For Port Scanning
connection_history = defaultdict(set)
# For Rate Limiting (Packets per second)
packet_counts = defaultdict(int)

alert_cooldown = {}
last_reset = time.time()
last_rate_reset = time.time()

def check_for_threats(data):
    global last_reset, last_rate_reset
    
    src = data["src_ip"]
    if src in WHITELIST or src.startswith("fe80") or src == "N/A":
        return "NORMAL"

    current_time = time.time()

    # 1. Rate Limit Logic (Reset every 1 second)
    if current_time - last_rate_reset > 1:
        packet_counts.clear()
        last_rate_reset = current_time
    
    packet_counts[src] += 1
    
    # If an IP sends more than 100 packets in a single second
    if packet_counts[src] > 100:
        if src not in alert_cooldown or (current_time - alert_cooldown[src] > 5):
            alert_cooldown[src] = current_time
            return "RATE_LIMIT_EXCEEDED"

    # 2. Port Scan Logic (Reset every 60 seconds)
    if current_time - last_reset > 60:
        connection_history.clear()
        alert_cooldown.clear()
        last_reset = current_time

    if data["protocol"] != "N/A":
        connection_history[src].add(data["dst_port"])
        if len(connection_history[src]) > 15:
            if src not in alert_cooldown or (current_time - alert_cooldown[src] > 5):
                alert_cooldown[src] = current_time
                return "POTENTIAL_PORT_SCAN"
    
    return "NORMAL"