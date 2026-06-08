from scapy.all import *
import pandas as pd
from sklearn.ensemble import IsolationForest
import glob
import matplotlib.pyplot as plt

# Read network traffic from PCAP-file
files = [file for file in glob.glob("C:/Users/melvi/Documents/VSC/Projekt/network-anomaly-detector/*.pcapng")]
packets = [] 
for file in files:
    packets += rdpcap(file)
    
# Extract relevant fields from each packet
rows = []
for p in packets:
    if p.haslayer("IP"):
        if p.haslayer("TCP"):
            protocol = "TCP"
        elif p.haslayer("UDP"):
            protocol = "UDP"
        else:
            protocol = "Other"
        row = {
            "time": float(p.time),
            "src_ip": p["IP"].src,
            "dst_ip": p["IP"].dst,
            "size": len(p),
            "protocol": protocol
        }
        rows.append(row)

# Build pandas DataFrame and set time as index
df = pd.DataFrame(rows)
df["time"] = pd.to_datetime(df["time"].astype(float), unit="s")
df = df.set_index("time")

# Aggregate features per second
features = pd.DataFrame ({
    "packets_per_sec": df.resample("1s").size(),
    "mean_size": df["size"].resample("1s").mean()
})

# Calculate amount of UDP-trafic per second
udp_per_sec = df[df["protocol"] == "UDP"].resample("1s").size()
features["udp_ratio"] = udp_per_sec / features["packets_per_sec"]
features = features.fillna(0)


# Train Isolation Forest and flag anomalies
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(features)

features["anomaly"] = model.predict(features)
# print(features[features["anomaly"] == -1])


plt.figure(figsize=(14, 5))

# Plot all normal traffic
normal = features[features["anomaly"] == 1]
plt.plot(features.index, features["packets_per_sec"], color="blue", label="Normal", linewidth=0.5)

# Highlight anomalies in red
anomalies = features[features["anomaly"] == -1]
plt.scatter(anomalies.index, anomalies["packets_per_sec"], color="red", label="Anomaly", s=10)

plt.title("Network Traffic Anomaly Detection")
plt.xlabel("Time")
plt.ylabel("Packets per second")
plt.legend()
plt.show()