from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

BLOCKED_IPS = ['192.168.186.129']
BLOCKED_PORTS = [80, 443]

def packet_filter(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Analyserer pakke fra {ip_src} til {ip_dst}...")

        if ip_src in BLOCKED_IPS or ip_dst in BLOCKED_IPS:
            print(f"Blokkerer pakke fra {ip_src} til {ip_dst}!")
            return

        if TCP in packet and packet[TCP].dport in BLOCKED_PORTS:
            print(f"Blokkerer TCP-pakke til port {packet[TCP].dport}")
            return

        if UDP in packet and packet[UDP].dport in BLOCKED_PORTS:
            print(f"Blokkerer UDP-pakke til port {packet[UDP].dport}")
            return

        print(f"Tillater pakke fra {ip_src} til {ip_dst}")

def start_firewall():
    print("Starter enkel brannmur...")
    sniff(prn=packet_filter, store=0)

if __name__ == "__main__":
    start_firewall()

