from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def analyze_packet(packet):
    # Check if packet contains IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print("\n==============================")
        print("📦 Packet Captured")
        print("==============================")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # TCP Protocol
        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")

            if packet[TCP].payload:
                print("Payload        :", bytes(packet[TCP].payload))

        # UDP Protocol
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

            if packet[UDP].payload:
                print("Payload        :", bytes(packet[UDP].payload))

        # ICMP Protocol
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        # Other Protocols
        else:
            print("Protocol       : Other")

def main():
    print("🚀 Network Sniffer Started")
    print("📌 Press CTRL + C to stop\n")

    # Start sniffing packets
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()