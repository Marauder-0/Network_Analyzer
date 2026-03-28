from scapy.all import sniff, conf
from parser import parse_packet
from detector import check_for_threats
from logger import log_to_file
import time

# Rich UI Imports
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console, Group
from rich.layout import Layout

console = Console()
stats = {"total": 0, "threats": 0, "start": time.time()}
recent_packets = [] 

def generate_dashboard():
    # 1. Create the Header Stats
    uptime = int(time.time() - stats["start"])
    stats_text = (
        f"[bold cyan]UPTIME:[/bold cyan] {uptime}s  |  "
        f"[bold white]TOTAL PACKETS:[/bold white] {stats['total']}  |  "
        f"[bold red]THREATS DETECTED:[/bold red] {stats['threats']}"
    )
    header = Panel(
        stats_text, 
        title="[bold blue]SENTINEL NIDS DASHBOARD[/bold blue]", 
        border_style="blue",
        padding=(1, 2)
    )

    # 2. Create the Live Traffic Table
    table = Table(expand=True, border_style="dim")
    table.add_column("Protocol", style="cyan", justify="center")
    table.add_column("Source IP", style="white")
    table.add_column("Dest Port", style="green", justify="right")
    table.add_column("Threat Status", style="bold yellow")

    # Show last 10 packets
    for p in recent_packets[-10:]: 
        threat_label = p['threat']
        color = "red" if threat_label != "NORMAL" else "white"
        
        table.add_row(
            str(p['protocol']), 
            str(p['src_ip']), 
            str(p['dst_port']), 
            f"[{color}]{threat_label}[/{color}]"
        )
    
    return Group(header, table)

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
        if len(recent_packets) > 20: 
            recent_packets.pop(0)

# --- THE MAIN LOOP ---
target_iface = r"\Device\NPF_Loopback"

# Clear the screen once before starting to remove any "ghost" text
console.clear()

# 'screen=True' creates a dedicated full-terminal buffer (like htop)
# This prevents the scrolling/doubling you are seeing.
with Live(generate_dashboard(), refresh_per_second=4, screen=True) as live:
    def live_callback(packet):
        packet_callback(packet)
        live.update(generate_dashboard())
    
    try:
        sniff(prn=live_callback, store=0, iface=target_iface)
    except KeyboardInterrupt:
        pass 

# Screen closes automatically, back to normal terminal
console.print("\n[bold red][!] Sentinel Shutting Down Safely...[/bold red]")