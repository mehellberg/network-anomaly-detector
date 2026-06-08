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


fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8))

# June 6
day1 = active["2026-06-06"]
anom1 = day1[day1["anomaly"] == -1]
ax1.plot(day1.index, day1["packets_per_sec"], color="blue", linewidth=0.5)
ax1.scatter(anom1.index, anom1["packets_per_sec"], color="red", s=10)
ax1.set_title("June 6")

# June 7
day2 = active["2026-06-07"]
anom2 = day2[day2["anomaly"] == -1]
ax2.plot(day2.index, day2["packets_per_sec"], color="blue", linewidth=0.5)
ax2.scatter(anom2.index, anom2["packets_per_sec"], color="red", s=10)
ax2.set_title("June 7")

plt.tight_layout()
plt.show()