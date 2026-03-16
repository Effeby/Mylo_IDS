import pandas as pd
import numpy as np
import os

top_features = [
    "src_bytes", "dst_bytes", "same_srv_rate", "dst_host_srv_count",
    "dst_host_same_srv_rate", "flag", "logged_in", "diff_srv_rate",
    "protocol_type", "count", "dst_host_count", "serror_rate",
    "dst_host_serror_rate", "srv_serror_rate", "dst_host_same_src_port_rate",
    "rerror_rate", "srv_count", "dst_host_rerror_rate",
    "dst_host_diff_srv_rate", "duration",
    "bytes_ratio", "bytes_per_packet", "serror_diff",
]

# NIDS dataset → 9 classes Mylo
# Web Attack → WebAttack (cohérent avec CICIDS2017)
label_map = {
    'Normal':     'Normal',
    'DoS':        'DoS',
    'Probe':      'Probe',
    'R2L':        'R2L',
    'U2R':        'U2R',
    'Web Attack': 'WebAttack',
}

print("=" * 55)
print("  MYLO — Préparation NIDS Dataset (9 classes)")
print("=" * 55)

print("\n[1/4] Chargement...")
df = pd.read_csv("ml/nids_dataset.csv")
print(f"      Lignes : {len(df):,}")
print(f"      Labels originaux :")
print(df["Label"].value_counts().to_string())

print("\n[2/4] Mapping labels...")
df["label_multi"] = df["Label"].map(label_map)
df = df[df["label_multi"].notna()]

print(f"\n      Distribution après mapping :")
print(df["label_multi"].value_counts().to_string())

print("\n[3/4] Construction des features...")
df_out = pd.DataFrame()
df_out["duration"]      = df["Duration"]
df_out["src_bytes"]     = df["SrcBytes"]
df_out["dst_bytes"]     = df["DstBytes"]
df_out["protocol_type"] = df["Protocol"]
df_out["srv_serror_rate"] = df["PSHFlagCount"]
df_out["count"]         = df["PacketsPerSec"]
df_out["bytes_ratio"]   = df["SrcBytes"] / (df["DstBytes"] + 1)
df_out["bytes_per_packet"] = df["SrcBytes"] / (df["PacketsPerSec"] + 1)
df_out["serror_diff"]   = 0.0
df_out["label_multi"]   = df["label_multi"].values

# Colonnes manquantes → 0
for col in top_features:
    if col not in df_out.columns:
        df_out[col] = 0.0

# Nettoyage
df_out.replace([np.inf, -np.inf], np.nan, inplace=True)
df_out.dropna(inplace=True)
print(f"      Lignes finales : {len(df_out):,}")

print("\n[4/4] Sauvegarde...")
os.makedirs("ml/data_prepared", exist_ok=True)
df_out[top_features + ["label_multi"]].to_csv(
    "ml/data_prepared/nids_prepared.csv", index=False
)
print("      → ml/data_prepared/nids_prepared.csv")

print("\n" + "=" * 55)
print("  NIDS Dataset prêt — 9 classes ✓")
print("=" * 55)