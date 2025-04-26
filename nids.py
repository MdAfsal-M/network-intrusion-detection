from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == 2:  # SYN flag
                print(f"[!] SYN Scan detected from {src} to {dst}")

            if packet[TCP].dport == 80:
                print(f"[!] HTTP request from {src} to {dst}")

        elif packet.haslayer(UDP):
            if packet.haslayer(DNS):
                print(f"[!] DNS Amplification pattern from {src} to {dst}")

        elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
            print(f"[!] ICMP Ping Sweep detected from {src} to {dst}")

print("🛡️  NIDS running... Press Ctrl+C to stop\n")
sniff(filter="ip", prn=packet_callback, store=0)
