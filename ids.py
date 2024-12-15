from scapy.all import sniff, IP
from collections import Counter
import time
import joblib
import pandas as pd

# Configuration
MONITOR_INTERFACE = "enp0s3"  # My network interface
PACKET_THRESHOLD = 100         # Max packets allowed per IP in TIME_WINDOW
TIME_WINDOW = 5               # Time window in seconds for counting packets

# Import ML model and vectorizer
intrusion_model = joblib.load("network_anomaly_detector.pkl")
vectorizer = joblib.load("info_vectorizer.pkl")

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
    
    # Process 'Info' column using the saved vectorizer
    info_tfidf = vectorizer.transform(new_data["Info"].fillna("")).toarray()
    
    # One-hot encode Protocol column
    new_data = pd.get_dummies(new_data, columns=["Protocol"], drop_first=True)
    
    # Combine processed features
    X_new = pd.concat(
        [pd.DataFrame(info_tfidf, columns=vectorizer.get_feature_names_out()), 
         new_data[["Length"]], 
         new_data.filter(regex="Protocol_")],
        axis=1
    )
    
    # Handle missing columns (fill with 0)
    expected_features = intrusion_model.feature_importances_.shape[0]
    X_new = X_new.reindex(columns=intrusion_model.feature_names_in_, fill_value=0)
    
    # Predict anomalies
    prediction = intrusion_model.predict(X_new)[0]
    
    return prediction

def process_packet(packet):
    """
    Processes a sniffed packet and checks for malicious activity using the ML model.
    """
    try:
        # Extract packet details
        protocol = packet[IP].proto if IP in packet else "Unknown"
        info = f"Packet from {packet[IP].src} to {packet[IP].dst}" if IP in packet else "Unknown Info"
        length = len(packet)

        # Create a DataFrame for prediction
        packet_data = pd.DataFrame([{
            "Info": info,
            "Length": length,
            "Protocol": protocol
        }])

        # Get prediction
        prediction = predict_network_activity(packet_data)

        # Print only if malicious
        if prediction == 1:
            print("Malicious activity detected!")

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    """
    Starts sniffing packets on the specified interface and calls the
    detection function for each captured packet.
    """
    print(f"Starting packet capture on interface {MONITOR_INTERFACE}...")
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=process_packet)

if __name__ == "__main__":
    new_data = pd.DataFrame({
    "Info": ["Destination Unreachable"],
    "Length": [128],
    "Protocol": ["ICMP"]
    })

    classification = predict_network_activity(new_data)
    print(f"Classification: {'Malicious' if classification == 1 else 'Normal'}")
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")
