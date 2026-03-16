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

# Ce fichier vient de CICIDS2017 (format CICFlowMeter identique)
# Label : 'DDoS' et 'BENIGN'
label_map = {
    'BENIGN': 'Normal', 'Benign': 'Normal', 'benign': 'Normal',
    'DDoS':   'DDoS',
    # Variantes possibles
    'DDos':   'DDoS', 'ddos': 'DDoS',
}

COL_MAP = {
    ' Flow Duration': 'duration', 'Flow Duration': 'duration',
    ' Total Fwd Packets': 'count', 'Total Fwd Packets': 'count',
    'Tot Fwd Pkts': 'count', ' Tot Fwd Pkts': 'count',
    ' Total Backward Packets': 'srv_count', 'Total Backward Packets': 'srv_count',
    'Tot Bwd Pkts': 'srv_count', ' Tot Bwd Pkts': 'srv_count',
    'Total Length of Fwd Packets': 'src_bytes',
    ' Total Length of Fwd Packets': 'src_bytes',
    'TotLen Fwd Pkts': 'src_bytes', ' TotLen Fwd Pkts': 'src_bytes',
    'Total Length of Bwd Packets': 'dst_bytes',
    ' Total Length of Bwd Packets': 'dst_bytes',
    'TotLen Bwd Pkts': 'dst_bytes', ' TotLen Bwd Pkts': 'dst_bytes',
    'SYN Flag Cnt': 'serror_rate', ' SYN Flag Cnt': 'serror_rate',
    'RST Flag Cnt': 'rerror_rate', ' RST Flag Cnt': 'rerror_rate',
    ' Label': 'label_raw', 'Label': 'label_raw',
}

SAMPLES = {
    'Normal': 20000,
    'DDoS':   50000,   # on prend beaucoup — c'est l'objectif de ce fichier
}

# ══════════════════════════════════════════════════════════════════
#  CHEMINS — fichier unique à la racine de D:
# ══════════════════════════════════════════════════════════════════
SOURCE_FILE = r'D:\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
OUTPUT_DIR  = r'D:\MYLO\ml\data_prepared'

print("=" * 60)
print("  MYLO — Préparation DDoS (Friday CICIDS2017)")
print(f"  Source : {SOURCE_FILE}")
print("=" * 60)

if not os.path.exists(SOURCE_FILE):
    print(f"\n❌  Fichier introuvable : {SOURCE_FILE}")
    print("    Vérifie que le fichier est bien à la racine de D:\\")
    exit(1)

size_mb = os.path.getsize(SOURCE_FILE) / (1024 * 1024)
print(f"\n[1/4] Chargement ({size_mb:.0f} MB)...")
try:
    df = pd.read_csv(SOURCE_FILE, encoding='utf-8', low_memory=False)
except UnicodeDecodeError:
    df = pd.read_csv(SOURCE_FILE, encoding='latin-1', low_memory=False)

df.columns = df.columns.str.strip()
print(f"  Colonnes : {len(df.columns)}  |  Lignes : {len(df):,}")

# Mapping colonnes
df = df.rename(columns={k: v for k, v in COL_MAP.items() if k in df.columns})
if 'label_raw' not in df.columns:
    lc = next((c for c in df.columns if 'label' in c.lower()), None)
    if lc:
        df = df.rename(columns={lc: 'label_raw'})
    else:
        print("❌  Colonne label introuvable :", df.columns.tolist()); exit(1)

print("\n[2/4] Labels...")
df['label_raw'] = df['label_raw'].astype(str).str.strip()
print("  Labels originaux :")
print(df['label_raw'].value_counts().to_string())
df['label_multi'] = df['label_raw'].map(label_map)
df = df[df['label_multi'].notna()]
print(f"\n  Distribution après mapping :")
print(df['label_multi'].value_counts().to_string())

print("\n[3/4] Construction des features...")

def safe(s): return pd.to_numeric(s, errors='coerce').fillna(0)

df_out = pd.DataFrame()
df_out['src_bytes']   = safe(df.get('src_bytes',   pd.Series(0, index=df.index)))
df_out['dst_bytes']   = safe(df.get('dst_bytes',   pd.Series(0, index=df.index)))
df_out['duration']    = safe(df.get('duration',    pd.Series(0, index=df.index)))
df_out['count']       = safe(df.get('count',       pd.Series(1, index=df.index)))
df_out['srv_count']   = safe(df.get('srv_count',   pd.Series(0, index=df.index)))
df_out['serror_rate'] = safe(df.get('serror_rate', pd.Series(0, index=df.index)))
df_out['rerror_rate'] = safe(df.get('rerror_rate', pd.Series(0, index=df.index)))

df_out['bytes_ratio']                 = df_out['src_bytes'] / (df_out['dst_bytes'] + 1)
df_out['bytes_per_packet']            = df_out['src_bytes'] / df_out['count'].clip(lower=1)
df_out['serror_diff']                 = df_out['serror_rate'] - df_out['rerror_rate']
df_out['dst_host_serror_rate']        = df_out['serror_rate']
df_out['srv_serror_rate']             = df_out['serror_rate']
df_out['dst_host_rerror_rate']        = df_out['rerror_rate']
df_out['dst_host_count']              = df_out['count'].clip(upper=255)
df_out['same_srv_rate']               = 1.0
df_out['dst_host_srv_count']          = 0.0
df_out['dst_host_same_srv_rate']      = 0.0
df_out['dst_host_same_src_port_rate'] = 0.0
df_out['dst_host_diff_srv_rate']      = 0.0
df_out['diff_srv_rate']               = 0.0
df_out['logged_in']                   = 0
df_out['flag']                        = 2      # SYN — typique DDoS
df_out['protocol_type']               = 2

for col in top_features:
    if col not in df_out.columns: df_out[col] = 0.0

df_out['label_multi'] = df['label_multi'].values
df_out.replace([np.inf, -np.inf], np.nan, inplace=True)
df_out.dropna(subset=top_features, inplace=True)
print(f"  Lignes après nettoyage : {len(df_out):,}")

print("\n[4/4] Échantillonnage...")
samples = []
for cls, n in SAMPLES.items():
    sub = df_out[df_out['label_multi'] == cls]
    if len(sub) == 0:
        print(f"  ⚠️  '{cls}' absente"); continue
    n_a = min(n, len(sub))
    samples.append(sub.sample(n=n_a, random_state=42))
    print(f"  {cls:10s} : {n_a:>8,} lignes")

df_final = pd.concat(samples, ignore_index=True).sample(frac=1, random_state=42)
print(f"\n  Total final : {len(df_final):,} lignes")

os.makedirs(OUTPUT_DIR, exist_ok=True)
out = os.path.join(OUTPUT_DIR, 'cicddos2019_prepared.csv')
df_final[top_features + ['label_multi']].to_csv(out, index=False)
print(f"\n  → {out}")
print("\n" + "=" * 60)
print("  DDoS Friday CICIDS2017 prêt ✓")
print("=" * 60)
