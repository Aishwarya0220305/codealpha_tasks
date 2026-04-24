from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

print("======================================")
print("   Network Packet Analyzer Started")
print("   Press CTRL + C to Stop")
print("======================================\n")

# Function to convert protocol number to name
def get_protocol_name(proto_number):
    if proto_number == 6:
        return "TCP"
    elif proto_number == 17:
        return "UDP"
    elif proto_number == 1:
        return "ICMP"
    else:
        return "Other"

# Function to analyze each captured packet
def analyze_packet(packet):

    print("\n" + "="*60)
    print("Packet Captured at:", datetime.now())
    print("="*60)

    # Check if IP layer exists
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol_number = ip_layer.proto
        protocol_name = get_protocol_name(protocol_number)

        print("Source IP        :", source_ip)
        print("Destination IP   :", destination_ip)
        print("Protocol         :", protocol_name)

        # TCP Protocol
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Source Port      :", tcp_layer.sport)
            print("Destination Port :", tcp_layer.dport)
            print("TCP Flags        :", tcp_layer.flags)

        # UDP Protocol
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Source Port      :", udp_layer.sport)
            print("Destination Port :", udp_layer.dport)

        # ICMP Protocol
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print("ICMP Type        :", icmp_layer.type)
            print("ICMP Code        :", icmp_layer.code)

        # Payload (Application Data)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload (first 50 bytes):", payload[:50])

    else:
        print("Non-IP Packet Detected")

# Start sniffing packets
sniff(prn=analyze_packet, store=False)