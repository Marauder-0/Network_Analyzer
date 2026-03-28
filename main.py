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
from rich.columns import Columns

console = Console()
stats = {"total": 0, "threats": 0, "start": time.time()}
recent_packets = [] 

def generate_dashboard():
    # 1. Create the Header Stats Panel
    uptime = int(time.time() - stats["start"])
    stats_text = f"UPTIME: {uptime}s | PACKETS: {stats['total']} | THREATS: {stats['threats']}"
    header = Panel(stats_text, title="[bold blue]SENTINEL NIDS[/bold blue]", border_style="blue")

    # 2. Create the Live Traffic Table
    table = Table(expand=True)
    table.add_column("Protocol", style="cyan", width=12)
    table.add_column("Source IP", style="magenta")
    table.add_column("Dest Port", style="green")
    table.add_column("Threat Status", style="bold yellow")

    for p in recent_packets[-10:]: # Keep it to 10 for clean UI
        color = "red" if p['threat'] != "NORMAL" else "white"
        table.add_row(
            p['protocol'], 
            p['src_ip'], 
            str(p['dst_port']), 
            f"[{color}]{p['threat']}[/{color}]"
        )
    
    # Combine Header and Table into one display
    return Columns([header, table], equal=False, expand=True)

def packet_callback(packet):
    global stats
    data = parse_packet(packet)
    
    if data["src_ip"] != "N/A":
        stats["total"] += 1
        threat = check_for_threats(data)
        
        if threat != "NORMAL":
            stats["threats"] += 1
            log_to_file(data, threat)
        
        data['threat'] = threat
        recent_packets.append(data)
        if len(recent_packets) > 15: recent_packets.pop(0)

# --- THE MAIN LOOP ---
target_iface = r"\Device\NPF_Loopback"

# Use 'transient=True' to clear the UI on exit
with Live(generate_dashboard(), refresh_per_second=4, vertical_overflow="visible") as live:
    def live_callback(packet):
        packet_callback(packet)
        live.update(generate_dashboard())
    
    try:
        sniff(prn=live_callback, store=0, iface=target_iface)
    except KeyboardInterrupt:
        pass # Exit the context to print the shutdown message

console.print("\n[bold red][!] Sentinel Shutting Down Safely...[/bold red]")