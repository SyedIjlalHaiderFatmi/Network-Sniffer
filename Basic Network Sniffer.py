from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer to analyze structure
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Identify the transport layer protocol
        protocol_name = "Other"
        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"

        print(f"[+] {protocol_name} Packet: {src_ip} -> {dst_ip}")

def main():
    print("--- Starting Network Sniffer ---")
    # Captures traffic and passes it to the callback function
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()