from scapy.all import sniff, IP
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Header print
print(Fore.GREEN + "\n💫 Sniffing started... Press Ctrl+C to stop.\n")
print(Fore.CYAN + f"{'Time':<10} {'Source':<18} {'Destination':<18} {'Proto':<6} {'Len':<6} {'TTL':<4}")
print("-" * 70)

# Protocol mapping
protocols = {6: "TCP", 17: "UDP", 1: "ICMP"}

def show_packet(packet):
    if IP in packet:
        time_now = datetime.now().strftime("%H:%M:%S")
        src = packet[IP].src
        dst = packet[IP].dst
        proto = protocols.get(packet[IP].proto, "Other")
        length = len(packet)
        ttl = packet[IP].ttl

        # Nicely formatted output row
        print(Fore.YELLOW + f"{time_now:<10} {src:<18} {dst:<18} {proto:<6} {length:<6} {ttl:<4}")

try:
    sniff(prn=show_packet, store=False, filter="ip")
except KeyboardInterrupt:
    print(Fore.RED + "\n\n🛑 Sniffing stopped by user.\n")