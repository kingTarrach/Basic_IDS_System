import pandas as pd

# Load the extracted traffic data
df = pd.read_csv("labeled_traffic.csv")

# Label attack traffic with destination as 10.0.0.2
# 10.0.0.2 was the destination ip address of my simulated attacks
df.loc[(df["Protocol"] == "ICMP") & 
       (df["Destination"] == "10.0.0.2"), 
       "Label"] = "Anomalous"
df.loc[(df["Protocol"] == "TCP") & 
    (df["Destination"] == "10.0.0.2"), 
    "Label"] = "Anomalous"
df.loc[(df["Protocol"] == "UDP") & 
       (df["Destination"] == "10.0.0.2"), 
        "Label"] = "Anomalous"

# Label attack traffic based on weird response data in info section combined with protocol

# Label ICMP traffic with "Destination Unreachable" as Anomalous
df.loc[(df["Protocol"] == "ICMP") & (df["Info"].str.contains("Destination unreachable", na=False)), "Label"] = "Anomalous"

# Label DNS traffic with "Unknown operation" as Anomalous
df.loc[(df["Protocol"] == "DNS") & (df["Info"].str.contains("Unknown operation", na=False)), "Label"] = "Anomalous"

# Label ICMP traffic with "no response found!" as Anomalous
df.loc[(df["Protocol"] == "ICMP") & (df["Info"].str.contains("no response found!", na=False)), "Label"] = "Anomalous"


# Save labeled data
df.to_csv("labeled_traffic_data.csv", index=False)
print("Labeled data saved to labeled_traffic_data.csv")
