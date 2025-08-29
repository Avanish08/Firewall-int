from scapy.all import sniff, IP, TCP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Packet: {ip_layer.src} --> {ip_layer.dst}, Port: {tcp_layer.dport}")

            # Simulate blocking
            if tcp_layer.dport in [22, 80]:
                print(f"[!] Blocked connection attempt to port {tcp_layer.dport} from {ip_layer.src}")

sniff(filter="ip", prn=process_packet, store=False)
