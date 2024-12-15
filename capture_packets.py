from scapy.all import sniff, IP, TCP, UDP
import csv
import time

# Configuration
CAPTURE_INTERFACE = "enp0s3"  # Your network interface
OUTPUT_FILE = "network_traffic.csv"
CAPTURE_DURATION = 600        # Capture time in seconds (e.g., 5 minutes)

# CSV Header
FIELDS = [
    "timestamp",         # Packet capture timestamp
    "src_ip",            # Source IP address
    "dst_ip",            # Destination IP address
    "protocol",          # Transport protocol (TCP/UDP/Other)
    "packet_length",     # Total length of the packet
    "src_port",          # Source port (if available)
    "dst_port",          # Destination port (if available)
]

def packet_to_row(packet):
    """
    Extract relevant information from a Scapy packet.
    """
    try:
        # Common fields
        timestamp = time.time()
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        packet_length = len(packet)
        
        # Protocol-specific fields
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"
            src_port = "N/A"
            dst_port = "N/A"
        
        return [timestamp, src_ip, dst_ip, protocol, packet_length, src_port, dst_port]
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def capture_traffic():
    """
    Sniff network traffic and save it to a CSV file.
    """
    print(f"Starting packet capture on interface {CAPTURE_INTERFACE}...")
    start_time = time.time()

    with open(OUTPUT_FILE, mode="w", newline="") as csv_file:
        print(f"Creating CSV file: {OUTPUT_FILE}")  # Debug log
        writer = csv.writer(csv_file)
        writer.writerow(FIELDS)  # Write CSV header

        def process_packet(packet):
            row = packet_to_row(packet)
            if row:
                writer.writerow(row)

        # Sniff packets for the specified duration
        sniff(iface=CAPTURE_INTERFACE, prn=process_packet, timeout=CAPTURE_DURATION)

    print(f"Packet capture complete. Data saved to {OUTPUT_FILE}.")

if __name__ == "__main__":
    try:
        print("Starting script...")
        capture_traffic()
    except KeyboardInterrupt:
        print("\nPacket capture interrupted. Exiting.")
