from scapy.all import sniff, conf
from parser import parse_packet
from detector import check_for_threats
from logger import log_to_file
import time

# Rich UI Imports
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console

console = Console()
stats = {"total": 0, "threats": 0, "start": time.time()}
recent_packets = [] # Store last 10 packets for the table

def generate_table():
    table = Table(title="Live Network Traffic", expand=True)
    table.add_column("Protocol", style="cyan", width=10)
    table.add_column("Source IP", style="magenta")
    table.add_column("Destination Port", style="green")
    table.add_column("Threat Status", style="bold yellow")

    for p in recent_packets[-12:]:
        color = "red" if p['threat'] != "NORMAL" else "white"
        table.add_row(
            p['protocol'], 
            p['src_ip'], 
            str(p['dst_port']), 
            f"[{color}]{p['threat']}[/{color}]"
        )
    return table

def packet_callback(packet):
    global stats
    data = parse_packet(packet)
    
    if data["src_ip"] != "N/A":
        stats["total"] += 1
        threat = check_for_threats(data)
        
        if threat != "NORMAL":
            stats["threats"] += 1
            log_to_file(data, threat)
        
        # Add to our UI list
        data['threat'] = threat
        recent_packets.append(data)
        if len(recent_packets) > 20: recent_packets.pop(0)

# --- THE MAIN LOOP ---
target_iface = r"\Device\NPF_Loopback"

print(f"Starting Sentinel TUI on {target_iface}...")

with Live(generate_table(), refresh_per_second=4) as live:
    def live_callback(packet):
        packet_callback(packet)
        live.update(generate_table())
    
    try:
        sniff(prn=live_callback, store=0, iface=target_iface)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Sentinel Shutting Down Safely...[/bold red]")