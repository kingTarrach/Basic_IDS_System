import pyshark
import pandas as pd
import time
from collections import Counter
from ML_algorithm import model as intrusion_model, vectorizer



# Configuration
MONITOR_INTERFACE = "enp0s3"  # My network interface

# Packet statistics
packet_counts = Counter()
start_time = time.time()

def predict_network_activity(new_data):
    """
    Predicts whether the given network activity is normal or anomalous.
    
    Parameters:
    new_data (DataFrame): New network activity data with columns ['Info', 'Length', 'Protocol']
    
    Returns:
    int: 1 for malicious, 0 for normal.
    """    
    
    # Rule 1: Label ICMP traffic with "Destination unreachable" as Anomalous
    if (new_data["Protocol"] == "ICMP") and ("Destination unreachable" in new_data["Info"]):
        return 1  # Malicious

    # Rule 2: Label DNS traffic with "Unknown operation" as Anomalous
    if (new_data["Protocol"] == "DNS") and ("Unknown operation" in new_data["Info"]):
        return 1  # Malicious

    # Rule 3: Label ICMP traffic with "no response found!" as Anomalous
    if (new_data["Protocol"] == "ICMP") and ("no response found!" in new_data["Info"]):
        return 1  # Malicious

    # If none of the rules match, label as Normal
    return 0  # Normal

def process_packet(packet):
    """
    Processes a sniffed packet using pyshark and checks for malicious activity using the ML model.
    """

    try:
        # Extract packet details
        protocol = packet.highest_layer
        info = f"Packet from {packet.ip.src} to {packet.ip.dst}" if hasattr(packet, "ip") else "Unknown Info"
        length = int(packet.length) if hasattr(packet, "length") else 0

        # Create a single data point as a dictionary
        packet_data = {"Info": info, "Length": length, "Protocol": protocol}

        # Get prediction (1 for malicious, 0 for normal)
        prediction = predict_network_activity(packet_data)

        # Print only if malicious
        if prediction == 1:
            print("Malicious activity detected!")
        else:
            print("Normal activity.")

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    """
    Starts sniffing packets on the specified interface and calls the
    detection function for each captured packet.
    """
    print(f"Starting packet capture on interface {MONITOR_INTERFACE}...")
    try:
        # Create a live capture object
        capture = pyshark.LiveCapture(interface=MONITOR_INTERFACE, debug=True)

        # Sniff packets continuously
        print("Hello")
        for packet in capture.sniff_continuously():
            try:
                if packet:
                    process_packet(packet)  # Process packets if captured
                else:
                    print("No packets captured yet...")
            except Exception as packet_error:
                print(f"Error processing packet: {packet_error}")
    except Exception as e:
        print(f"Error during sniffing: {e}")

def simulate_attacks():
    # ICMP Flood Attack DataFrame
    icmp_flood_data = [
        {"Info": "Destination unreachable", "Length": 120, "Protocol": "ICMP"},
        {"Info": "Destination unreachable", "Length": 120, "Protocol": "ICMP"},
        {"Info": "Destination unreachable", "Length": 120, "Protocol": "ICMP"},
    ]

    # SYN Flood Attack DataFrame
    syn_flood_data = [
        {"Info": "Unknown operation", "Length": 64, "Protocol": "TCP"},
        {"Info": "Unknown operation", "Length": 64, "Protocol": "TCP"},
        {"Info": "Unknown operation", "Length": 64, "Protocol": "TCP"},
    ]

    # UDP Flood Attack DataFrame
    udp_flood_data = [
        {"Info": "no response found!", "Length": 120, "Protocol": "UDP"},
        {"Info": "no response found!", "Length": 120, "Protocol": "UDP"},
        {"Info": "no response found!", "Length": 120, "Protocol": "UDP"},
    ]

    # ICMP Flood Predictions
    print("ICMP Flood Predictions:")
    for packet in icmp_flood_data:
        prediction = predict_network_activity(packet)
        print(f"Prediction: {'Malicious' if prediction == 1 else 'Normal'}")

    # SYN Flood Predictions
    print("\nSYN Flood Predictions:")
    for packet in syn_flood_data:
        prediction = predict_network_activity(packet)
        print(f"Prediction: {'Malicious' if prediction == 1 else 'Normal'}")

    # UDP Flood Predictions
    print("\nUDP Flood Predictions:")
    for packet in udp_flood_data:
        prediction = predict_network_activity(packet)
        print(f"Prediction: {'Malicious' if prediction == 1 else 'Normal'}")


if __name__ == "__main__":
    simulate_attacks()
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")
