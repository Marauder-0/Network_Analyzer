from scapy.all import IP, IPv6, TCP, UDP, Raw, Ether

def parse_packet(packet):
    # Added "src_mac" to the data dictionary
    data = {
        "protocol": "N/A", 
        "src_ip": "N/A", 
        "dst_ip": "N/A", 
        "src_port": "N/A", 
        "dst_port": "N/A", 
        "src_mac": "N/A", 
        "payload": ""
    }

    # 1. Extract MAC Address (Layer 2)
    if packet.haslayer(Ether):
        data["src_mac"] = packet[Ether].src

    # 2. Extract IP Addresses (Layer 3)
    if packet.haslayer(IP):
        data["src_ip"], data["dst_ip"] = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        data["src_ip"], data["dst_ip"] = packet[IPv6].src, packet[IPv6].dst

    # 3. Extract Ports & Protocols (Layer 4)
    if packet.haslayer(TCP):
        data["protocol"], data["src_port"], data["dst_port"] = "TCP", packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        data["protocol"], data["src_port"], data["dst_port"] = "UDP", packet[UDP].sport, packet[UDP].dport

    # 4. Extract Raw Data
    if packet.haslayer(Raw):
        try:
            data["payload"] = packet[Raw].load.decode('utf-8', errors='ignore')
        except:
            pass
            
    return data