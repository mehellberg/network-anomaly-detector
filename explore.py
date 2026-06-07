from scapy.all import *
import pandas as pd

paket = rdpcap("C:/Users/melvi/Documents/VSC/Projekt/network-anomaly-detector/capture.pcapng")

rader = []

for p in paket:
    if p.haslayer("IP"):
        if p.haslayer("TCP"):
            protokoll = "TCP"
        elif p.haslayer("UDP"):
            protokoll = "UDP"
        else:
            protokoll = "Annat"
        rad = {
            "tid": float(p.time),
            "src_ip": p["IP"].src,
            "dst_ip": p["IP"].dst,
            "storlek": len(p),
            "protokoll": protokoll
        }
        rader.append(rad)

df = pd.DataFrame(rader)
df["tid"] = pd.to_datetime(df["tid"].astype(float), unit="s")

print(df.head(10))
print(df["protokoll"].value_counts())
print(df["dst_ip"].value_counts().head(5))

df = df.set_index("tid")
paket_per_sekund = df.resample("1s").size()
print(paket_per_sekund.head(10))

features = pd.DataFrame ({
    "paket_per_sek": df.resample("1s").size(),
    "snitt_storlek": df["storlek"].resample("1s").mean()
})

udp_per_sek = df[df["protokoll"] == "UDP"].resample("1s").size()
features["andel_udp"] = udp_per_sek / features["paket_per_sek"]

features = features.fillna(0)
print(features.head(10))


from sklearn.ensemble import IsolationForest

modell = IsolationForest(contamination=0.05, random_state=42)
modell.fit(features)

features["anomali"] = modell.predict(features)
print(features[features["anomali"] == -1])