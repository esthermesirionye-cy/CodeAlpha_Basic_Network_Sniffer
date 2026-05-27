from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        protocol_name = "Unknown"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"
            
        print(f"\n[+] New Packet: {ip_src} -> {ip_dst} | Protocol: {protocol_name}")
        
        if packet.haslayer(TCP):
            payload = packet[TCP].payload
            if payload:
                print(f"    [TCP Payload Preview]: {str(payload)[:100]}")
                
        elif packet.haslayer(UDP):
            payload = packet[UDP].payload
            if payload:
                print(f"    [UDP Payload Preview]: {str(payload)[:100]}")
                
        elif packet.haslayer(ICMP):
            print("    [ICMP] Ping request/reply detected.")

def main():
    print("*" * 50)
    print("  CodeAlpha - Basic Network Sniffer Starting... ")
    print("  Press Ctrl+C to stop sniffing.")
    print("*" * 50)
    
    # Using Scapy to sniff traffic system-wide
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
