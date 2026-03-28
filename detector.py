from collections import defaultdict
import time
import yaml
import os

# Load configuration
def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

# Setup thresholds from config
WHITELIST = set(config['network']['whitelist'])
PORT_THRESHOLD = config['settings']['port_threshold']
RATE_THRESHOLD = config['settings']['rate_threshold']
COOLDOWN = config['settings']['alert_cooldown']

# Tracking dictionaries
connection_history = defaultdict(set)
packet_counts = defaultdict(int)
ip_mac_map = {}  # NEW: Tracks {IP: MAC_Address} for ARP Spoof detection
alert_cooldown = {}

# Time markers
last_reset = time.time()
last_rate_reset = time.time()

def check_for_threats(data):
    global last_reset, last_rate_reset
    
    src_ip = data["src_ip"]
    src_mac = data.get("src_mac", "N/A") # Ensure your parser passes src_mac
    
    # 1. Config-based Whitelisting
    if src_ip in WHITELIST or src_ip == "N/A":
        return "NORMAL"
    if config['network']['ignore_ipv6'] and src_ip.startswith("fe80"):
        return "NORMAL"

    current_time = time.time()

    # 2. ARP Spoofing Detection (New Feature)
    # If the same IP address suddenly shows up with a different MAC address
    if src_mac != "N/A":
        if src_ip in ip_mac_map:
            if ip_mac_map[src_ip] != src_mac:
                if src_ip not in alert_cooldown or (current_time - alert_cooldown[src_ip] > COOLDOWN):
                    alert_cooldown[src_ip] = current_time
                    return "ARP_SPOOF_DETECTED"
        else:
            ip_mac_map[src_ip] = src_mac

    # 3. Rate Limit Logic (Reset every 1 second)
    if current_time - last_rate_reset > 1:
        packet_counts.clear()
        last_rate_reset = current_time
    
    packet_counts[src_ip] += 1
    if packet_counts[src_ip] > RATE_THRESHOLD:
        if src_ip not in alert_cooldown or (current_time - alert_cooldown[src_ip] > COOLDOWN):
            alert_cooldown[src_ip] = current_time
            return "RATE_LIMIT_EXCEEDED"

    # 4. Port Scan Logic (Reset every 60 seconds)
    if current_time - last_reset > 60:
        connection_history.clear()
        alert_cooldown.clear()
        last_reset = current_time

    if data["protocol"] != "N/A":
        connection_history[src_ip].add(data["dst_port"])
        if len(connection_history[src_ip]) > PORT_THRESHOLD:
            if src_ip not in alert_cooldown or (current_time - alert_cooldown[src_ip] > COOLDOWN):
                alert_cooldown[src_ip] = current_time
                return "POTENTIAL_PORT_SCAN"
    
    return "NORMAL"