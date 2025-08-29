from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP

# Define blocked IPs or ports
BLOCKED_IPS = {"192.168.1.10"}
BLOCKED_PORTS = {22, 23, 80}  # SSH, Telnet, HTTP

def packet_callback(packet):
    scapy_packet = IP(packet.get_payload())

    # Check if packet is TCP or UDP
    if scapy_packet.haslayer(TCP) or scapy_packet.haslayer(UDP):
        layer = scapy_packet[TCP] if scapy_packet.haslayer(TCP) else scapy_packet[UDP]
        
        # Block based on IP or port
        if scapy_packet.src in BLOCKED_IPS or layer.dport in BLOCKED_PORTS:
            print(f"[!] Dropped packet from {scapy_packet.src} to port {layer.dport}")
            packet.drop()
            return

    # Accept other packets
    packet.accept()

def start_firewall():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, packet_callback)

    try:
        print("[*] Firewall is running...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping firewall...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    start_firewall()
