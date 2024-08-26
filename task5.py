from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].load if hasattr(packet[IP], 'load') else None
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        if protocol == 6:  # TCP
            print("Protocol: TCP")
            if TCP in packet:
                print(f"Source Port: {packet[TCP].sport}")
                print(f"Destination Port: {packet[TCP].dport}")
        elif protocol == 17:  # UDP
            print("Protocol: UDP")
            if UDP in packet:
                print(f"Source Port: {packet[UDP].sport}")
                print(f"Destination Port: {packet[UDP].dport}")

        if payload:
            print(f"Payload Data: {payload.decode(errors='ignore')}")
        
        print("\n" + "="*50 + "\n")

# Sniff packets on the network
sniff(prn=packet_callback, store=0, count=10)  # Adjust count as needed