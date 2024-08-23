from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the protocol (TCP, UDP, etc.)
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = "Other"
        
        print(f"[+] Protocol: {proto_name}, Source: {ip_src}, Destination: {ip_dst}")
        
        # Extract and print payload data if available
        if Raw in packet:
            payload_data = packet[Raw].load
            print(f"Payload: {payload_data}\n")

def start_sniffing(interface):
    """Start sniffing packets on the specified network interface."""
    print(f"[*] Starting packet sniffing on {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

# Example usage:
network_interface = "eth0"  # Replace with the correct interface name for your system
start_sniffing(network_interface)
