import scapy.all as scapy

def packet_sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"Payload: {payload.hex()}")

packet_sniffer("Wi-Fi")
