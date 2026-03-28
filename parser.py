from scapy.all import IP, IPv6, TCP, UDP, Raw

def parse_packet(packet):
    data = {"protocol": "N/A", "src_ip": "N/A", "dst_ip": "N/A", "src_port": "N/A", "dst_port": "N/A", "payload": ""}

    if packet.haslayer(IP):
        data["src_ip"], data["dst_ip"] = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        data["src_ip"], data["dst_ip"] = packet[IPv6].src, packet[IPv6].dst

    if packet.haslayer(TCP):
        data["protocol"], data["src_port"], data["dst_port"] = "TCP", packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        data["protocol"], data["src_port"], data["dst_port"] = "UDP", packet[UDP].sport, packet[UDP].dport

    if packet.haslayer(Raw):
        try:
            data["payload"] = packet[Raw].load.decode('utf-8', errors='ignore')
        except:
            pass
    return data