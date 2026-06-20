#!/usr/bin/env python3
import os
import sys
import shutil
import threading
import subprocess
from scapy.all import sniff, ARP

# In-memory database to store unique IP-to-MAC mappings
network_ledger = {}

# Custom mapping explicitly tuned to your environment's hardware footprint
DEVICE_LABELS = {
    # System Core Components
    "6c:55:e8": "🚨 [ROUTER / GATEWAY] (Comcast Xfinity)",
    "68:54:5a": "💻 YOUR LINUX PC (Intel Wireless Controller)",
    
    # Smart Media Elements & Entertainment
    "60:92:c8": "📺 SMART TV / ROKU STREAMER",
    "c0:d2:f3": "📺 SMART TV (Vizio / Hisense / TCL Media Chip)",
    "74:ec:b2": "🔥 AMAZON DEVICE (Fire Stick / Echo Smart Hub)",
    
    # Generic placeholders for future household targets
    "b4:79:a7": "🍳 SMART OVEN / APPLIANCE",
    "50:c7:bf": "🔌 SMART PLUG / IoT NODE",
    "1c:5a:3e": "📺 SMART TV (Samsung)",
    "34:fc:ef": "📺 SMART TV (LG)"
}

def clear_screen():
    """Clears terminal interface for a clean tracking dashboard."""
    os.system('clear' if os.name == 'posix' else 'cls')

def get_label(ip, mac):
    """Normalizes address formats and handles identification logic."""
    mac_lower = mac.lower().strip()
    prefix = mac_lower[:8]  # Extracts the first 8 characters ('xx:xx:xx')
    
    if ip.endswith('.1'):
        return DEVICE_LABELS.get("6c:55:e8", "🚨 [ROUTER / GATEWAY]")
        
    if prefix in DEVICE_LABELS:
        return DEVICE_LABELS[prefix]
        
    return "Unknown Device Node"

def display_matrix():
    """Renders the formatted, non-duplicate tracking interface."""
    clear_screen()
    print("=" * 85)
    print("               AUTOMATED HARDWARE LOGISTICS MATRIX              ")
    print("=" * 85)
    print(f" [*] Sniffing Broadcast Airspace... Total Discovered: {len(network_ledger)}")
    print("-" * 85)
    print(f"{'IP ADDRESS':<16}{'HARDWARE MAC':<22}{'IDENTIFIED DEVICE TYPE':<30}")
    print("-" * 85)
    
    # Sort numerically by IP segment blocks
    try:
        sorted_nodes = sorted(network_ledger.items(), key=lambda x: [int(n) for n in x.split('.') if n.isdigit()])
    except Exception:
        sorted_nodes = sorted(network_ledger.items())

    for ip, mac in sorted_nodes:
        identity = get_label(ip, mac)
        print(f"{ip:<16}{mac:<22}{identity:<30}")
    print("=" * 85)

def parse_packet(packet):
    """Processes low-level incoming Address Resolution Protocol frames."""
    if packet.haslayer(ARP):
        arp = packet[ARP]
        has_new_data = False

        ip_addr = arp.psrc
        mac_addr = arp.hwsrc

        if ip_addr != "0.0.0.0" and mac_addr != "00:00:00:00:00:00":
            if ip_addr not in network_ledger or network_ledger[ip_addr] != mac_addr:
                network_ledger[ip_addr] = mac_addr
                has_new_data = True

        if has_new_data:
            display_matrix()
            # Keep instructions visible at the bottom when updates refresh the screen
            print(" Hold Ctrl+C to terminate monitor mode session safely.")

def execute_silent_sweep():
    """Worker function tasked with running the actual broadcast commands."""
    if shutil.which("fping"):
        subprocess.run(["fping", "-g", "10.0.0.0/24", "-a"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["ping", "-b", "-c", "4", "10.0.0.255"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def prompt_sweep():
    """Prompts the user for input without halting main thread sniffing."""
    try:
        user_choice = input("\n[?] Run active discovery sweep to wake up sleeping devices? (Y/N): ").strip().lower()
        if user_choice == 'y':
            # Spin up background execution thread so packet processing never locks
            sweep_thread = threading.Thread(target=execute_silent_sweep, daemon=True)
            sweep_thread.start()
            display_matrix()
            print(" [*] Background sweep initiated... Devices will populate below as they wake up.")
            print("=" * 85)
        else:
            display_matrix()
            print(" [*] Passive monitoring active. Waiting for organic network chatter...")
            print("=" * 85)
        print(" Hold Ctrl+C to terminate monitor mode session safely.")
    except (KeyboardInterrupt, EOFError):
        pass

def run():
    if os.getuid() != 0:
        print("\n[!] Failure: Administrative root privileges needed for raw socket capture.")
        print("    Execute via command: sudo python3 sniff.py")
        sys.exit(1)

    # 1. Render the initial matrix instantly
    display_matrix()
    
    # 2. Launch the asynchronous sniffer thread
    sniff_thread = threading.Thread(
        target=lambda: sniff(filter="arp", prn=parse_packet, store=0), 
        daemon=True
    )
    sniff_thread.start()
    
    # 3. Present the prompt clean right underneath the loaded table
    prompt_sweep()

    # 4. Keep main execution loop alive to listen for Ctrl+C exit signals
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Monitor sessions closed.")
        sys.exit(0)

if __name__ == "__main__":
    run()
