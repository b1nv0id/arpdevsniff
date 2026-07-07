#!/usr/bin/env python3
import os
import re
import sys
import shutil
import socket
import threading
import subprocess
import time
from scapy.all import sniff, ARP, conf

# In-memory database to store unique IP-to-MAC mappings
network_ledger = {}

# Generic, non-personalized OUI-style labels (first 3 MAC octets)
# Labels are category hints, not strict truth.
DEVICE_LABELS = {
    # Network infra
    "6c:55:e8": ("🚨 Router / Gateway-Class Device", "medium"),
    "dc:a6:32": ("📡 Network Infrastructure Device", "medium"),
    "f4:f5:e8": ("📡 Network Infrastructure Device", "medium"),

    # Compute endpoints / virtualization
    "68:54:5a": ("💻 Laptop / Desktop-Class Device", "medium"),
    "00:50:56": ("🧪 Virtual Machine Host/Guest", "high"),
    "08:00:27": ("🧪 Virtual Machine Host/Guest", "high"),

    # Smart media / consumer tech
    "60:92:c8": ("📺 Smart TV / Media Streamer", "medium"),
    "c0:d2:f3": ("📺 Smart TV / Media Streamer", "medium"),
    "74:ec:b2": ("🔥 Smart Assistant / Streaming Device", "medium"),

    # IoT / appliances
    "b4:79:a7": ("🍳 Smart Appliance-Class Device", "medium"),
    "50:c7:bf": ("🔌 Smart Plug / IoT Node", "medium"),
    "1c:5a:3e": ("📺 Smart TV-Class Device", "medium"),
    "34:fc:ef": ("📺 Smart TV-Class Device", "medium"),
}

# Optional local OUI cache file path.
# Supported lines (examples):
#   E25389 Vendor Name
#   E2-53-89 Vendor Name
#   E2:53:89 Vendor Name
OUI_CACHE_FILE = "oui.txt"

# Runtime-discovered default gateway (if resolvable)
DEFAULT_GATEWAY_IP = None


def clear_screen():
    """Clears terminal interface for a clean tracking dashboard."""
    os.system("clear" if os.name == "posix" else "cls")


def normalize_oui_prefix(mac):
    """Returns MAC prefix as xx:xx:xx or empty string."""
    mac_lower = (mac or "").lower().strip()
    if len(mac_lower) < 8:
        return ""
    return mac_lower[:8]


def load_local_oui_map(path=OUI_CACHE_FILE):
    """
    Loads a tiny local OUI map from a plaintext file.
    Returns dict: 'xx:xx:xx' -> 'Vendor Name'
    """
    result = {}
    if not os.path.isfile(path):
        return result

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                # Match first token as 6 hex bytes with optional separators
                m = re.match(r"^([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2})\s+(.+)$", line)
                if not m:
                    continue

                token, vendor = m.group(1), m.group(2).strip()
                hex_only = re.sub(r"[^0-9A-Fa-f]", "", token).lower()
                if len(hex_only) != 6:
                    continue

                key = f"{hex_only[0:2]}:{hex_only[2:4]}:{hex_only[4:6]}"
                result[key] = vendor
    except Exception:
        pass

    return result


LOCAL_OUI_MAP = load_local_oui_map()


def get_default_gateway_linux():
    """
    Reads /proc/net/route to determine default gateway on Linux.
    Returns gateway IP string or None.
    """
    route_file = "/proc/net/route"
    if not os.path.exists(route_file):
        return None

    try:
        with open(route_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) < 3:
                    continue
                destination = fields[1]
                gateway_hex = fields[2]
                if destination != "00000000":
                    continue

                # Gateway is little-endian hex
                gw_int = int(gateway_hex, 16)
                gw_ip = socket.inet_ntoa(gw_int.to_bytes(4, byteorder="little"))
                return gw_ip
    except Exception:
        return None

    return None


def detect_default_gateway():
    """Best-effort gateway detection, then fallback to None."""
    # Linux-accurate path first
    gw = get_default_gateway_linux()
    if gw:
        return gw

    # Scapy route table fallback
    try:
        route = conf.route.route("0.0.0.0")
        # route is typically (dst, gw, iface, src)
        if len(route) > 1 and route[1] and route[1] != "0.0.0.0":
            return route[1]
    except Exception:
        pass

    return None


def format_with_confidence(label, confidence):
    return f"{label} [{confidence}]"


def get_label(ip, mac):
    """Applies generic identification logic with confidence scoring."""
    prefix = normalize_oui_prefix(mac)

    # High-confidence: detected system default gateway
    if DEFAULT_GATEWAY_IP and ip == DEFAULT_GATEWAY_IP:
        return format_with_confidence("🚨 Default Gateway / Router", "high")

    # Medium-confidence: static category hint by known OUI
    if prefix in DEVICE_LABELS:
        label, conf_score = DEVICE_LABELS[prefix]
        return format_with_confidence(label, conf_score)

    # Medium-confidence: local cache vendor name
    if prefix in LOCAL_OUI_MAP:
        vendor = LOCAL_OUI_MAP[prefix]
        return format_with_confidence(f"🏷️ Vendor Identified: {vendor}", "medium")

    # Low-confidence fallback for private ranges
    if ip.startswith(("10.", "192.168.", "172.")):
        return format_with_confidence("🛰️ Local Network Device (Unclassified)", "low")

    return format_with_confidence("Unknown Device Node", "low")


def display_matrix():
    """Renders the formatted, non-duplicate tracking interface."""
    clear_screen()
    print("=" * 101)
    print("                         AUTOMATED HARDWARE LOGISTICS MATRIX                         ")
    print("=" * 101)
    print(f" [*] Sniffing Broadcast Airspace... Total Discovered: {len(network_ledger)}")
    print("-" * 101)
    print(f"{'IP ADDRESS':<16}{'HARDWARE MAC':<22}{'IDENTIFIED DEVICE TYPE':<55}")
    print("-" * 101)

    # Sort numerically by IP octets
    def ip_sort_key(item):
        ip = item[0]
        try:
            return [int(n) for n in ip.split(".")]
        except Exception:
            return [999, 999, 999, 999]

    for ip, mac in sorted(network_ledger.items(), key=ip_sort_key):
        identity = get_label(ip, mac)
        print(f"{ip:<16}{mac:<22}{identity:<55}")
    print("=" * 101)


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
            print(" Hold Ctrl+C to terminate monitor mode session safely.")


def execute_silent_sweep():
    """Worker function tasked with running broadcast commands."""
    # Keeping your original defaults for same operational feel
    if shutil.which("fping"):
        subprocess.run(
            ["fping", "-g", "10.0.0.0/24", "-a"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            ["ping", "-b", "-c", "4", "10.0.0.255"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def prompt_sweep():
    """Prompts the user for input without halting main thread sniffing."""
    try:
        user_choice = input("\n[?] Run active discovery sweep to wake up sleeping devices? (Y/N): ").strip().lower()
        if user_choice == "y":
            # Spin up background execution thread so packet processing never locks
            sweep_thread = threading.Thread(target=execute_silent_sweep, daemon=True)
            sweep_thread.start()
            display_matrix()
            print(" [*] Background sweep initiated... Devices will populate below as they wake up.")
            print("=" * 101)
        else:
            display_matrix()
            print(" [*] Passive monitoring active. Waiting for organic network chatter...")
            print("=" * 101)
        print(" Hold Ctrl+C to terminate monitor mode session safely.")
    except (KeyboardInterrupt, EOFError):
        pass


def run():
    global DEFAULT_GATEWAY_IP

    if os.getuid() != 0:
        print("\n[!] Failure: Administrative root privileges needed for raw socket capture.")
        print("    Execute via command: sudo python3 arpdevsniff.py")
        sys.exit(1)

    DEFAULT_GATEWAY_IP = detect_default_gateway()

    # 1. Render the initial matrix instantly
    display_matrix()
    if DEFAULT_GATEWAY_IP:
        print(f" [*] Gateway fingerprint loaded: {DEFAULT_GATEWAY_IP}")
    else:
        print(" [*] Gateway fingerprint unavailable: falling back to heuristic classification.")
    if LOCAL_OUI_MAP:
        print(f" [*] Local OUI cache loaded: {len(LOCAL_OUI_MAP)} entries from '{OUI_CACHE_FILE}'")
    else:
        print(f" [*] No local OUI cache loaded (optional file missing/empty: '{OUI_CACHE_FILE}')")
    print("=" * 101)

    # 2. Launch the asynchronous sniffer thread
    sniff_thread = threading.Thread(
        target=lambda: sniff(filter="arp", prn=parse_packet, store=0),
        daemon=True,
    )
    sniff_thread.start()

    # 3. Present the prompt clean right underneath the loaded table
    prompt_sweep()

    # 4. Keep main execution loop alive to listen for Ctrl+C exit signals
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Monitor sessions closed.")
        sys.exit(0)


if __name__ == "__main__":
    run()
