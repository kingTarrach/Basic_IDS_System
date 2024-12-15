import pandas as pd

# Input and output file paths
INPUT_CSV = "network_traffic_data.csv"
OUTPUT_CSV = "labeled_traffic_data.csv"

def process_csv(input_csv):
    """
    Reads traffic data from a CSV file, processes it, and returns a DataFrame.
    """
    # Load the CSV file into a DataFrame
    df = pd.read_csv(input_csv)

    # Ensure the columns exist (adjust based on your CSV file's structure)
    required_columns = ["Time", "Source", "Destination", "Protocol", "Label" "Length"]
    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' not found in input file")

    # Process data (e.g., clean up or normalize)
    df["Source"] = df["Source"].fillna("N/A")  # Fill missing ports with "N/A"
    df["Destination"] = df["Destination"].fillna("N/A")

    # Optionally: Add any additional computed columns or labels
    # Example: Add a placeholder "Label" column
    df["Label"] = "Normal"  # Default to "Normal" for all traffic

    return df

# Process the CSV file and save to output
df = process_csv(INPUT_CSV)
df.to_csv(OUTPUT_CSV, index=False)
print(f"Processed traffic data saved to {OUTPUT_CSV}")
