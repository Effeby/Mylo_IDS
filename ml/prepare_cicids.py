import pandas as pd
import numpy as np
import os

# ─── MAPPING CICIDS2017 → 9 CLASSES MYLO ─────────────────────────────
label_map = {
    'BENIGN':                      'Normal',
    'DoS Hulk':                    'DoS',
    'DoS GoldenEye':               'DoS',
    'DoS slowloris':               'DoS',
    'DoS Slowhttptest':            'DoS',
    'DDoS':                        'DDoS',
    'PortScan':                    'Probe',
    'FTP-Patator':                 'BruteForce',
    'SSH-Patator':                 'BruteForce',
    'Web Attack_Brute Force':      'WebAttack',
    'Web Attack_XSS':              'WebAttack',
    'Web Attack_Sql Injection':    'WebAttack',
    'Bot':                         'Botnet',
    'Infiltration':                'Infiltration',
    'Heartbleed':                  'Infiltration',
}

# Colonnes CICIDS2017 → top_features NSL-KDD
# On mappe ce qui est compatible, le reste → 0
COL_MAP = {
    ' Flow Duration':              'duration',
    ' Total Fwd Packets':          'count',
    ' Total Backward Packets':     'srv_count',
    'Total Length of Fwd Packets': 'src_bytes',
    ' Total Length of Bwd Packets':'dst_bytes',
    ' Flow Packets/s':             'packets_per_sec',
    'Flow Bytes/s':                'bytes_per_sec',
    ' Label':                      'label_raw',
}

top_features = [
    "src_bytes", "dst_bytes", "same_srv_rate", "dst_host_srv_count",
    "dst_host_same_srv_rate", "flag", "logged_in", "diff_srv_rate",
    "protocol_type", "count", "dst_host_count", "serror_rate",
    "dst_host_serror_rate", "srv_serror_rate", "dst_host_same_src_port_rate",
    "rerror_rate", "srv_count", "dst_host_rerror_rate",
    "dst_host_diff_srv_rate", "duration",
    "bytes_ratio", "bytes_per_packet", "serror_diff",
]

# Échantillonnage par classe (équilibré)
SAMPLES = {
    'Normal':      30000,
    'DoS':         20000,
    'DDoS':        15000,
    'Probe':       15000,
    'BruteForce':  10000,
    'WebAttack':    5000,
    'Botnet':       1966,   # tout ce qu'on a
    'Infiltration':   47,   # tout ce qu'on a
}

print("=" * 55)
print("  MYLO — Préparation CICIDS2017 (9 classes)")
print("=" * 55)

print("\n[1/5] Chargement CICIDS2017...")
# Charger uniquement les colonnes utiles + Label
cols_to_load = list(COL_MAP.keys())
df = pd.read_csv(
    'ml/cicids2017/combinenew.csv',
    encoding='cp1252',
    usecols=cols_to_load,
    low_memory=False
)
df.columns = [COL_MAP.get(c, c) for c in df.columns]
print(f"      Lignes chargées : {len(df):,}")

print("\n[2/5] Mapping des labels...")
df['label_multi'] = df['label_raw'].map(label_map)
df = df[df['label_multi'].notna()]

print("      Distribution originale :")
print(df['label_multi'].value_counts().to_string())

print("\n[3/5] Construction des features...")
df_out = pd.DataFrame()

# Features disponibles depuis CICIDS2017
df_out['src_bytes']   = pd.to_numeric(df['src_bytes'],   errors='coerce').fillna(0)
df_out['dst_bytes']   = pd.to_numeric(df['dst_bytes'],   errors='coerce').fillna(0)
df_out['duration']    = pd.to_numeric(df['duration'],    errors='coerce').fillna(0)
df_out['count']       = pd.to_numeric(df['count'],       errors='coerce').fillna(0)
df_out['srv_count']   = pd.to_numeric(df['srv_count'],   errors='coerce').fillna(0)

# Features engineerées
df_out['bytes_ratio']      = df_out['src_bytes'] / (df_out['dst_bytes'] + 1)
df_out['bytes_per_packet'] = df_out['src_bytes'] / (df_out['count'] + 1)
df_out['serror_diff']      = 0.0  # pas disponible dans CICIDS2017

# Features NSL-KDD non disponibles → 0
for col in top_features:
    if col not in df_out.columns:
        df_out[col] = 0.0

df_out['label_multi'] = df['label_multi'].values

# Nettoyage
df_out.replace([np.inf, -np.inf], np.nan, inplace=True)
df_out.dropna(inplace=True)
print(f"      Lignes après nettoyage : {len(df_out):,}")

print("\n[4/5] Échantillonnage équilibré...")
samples = []
for cls, n in SAMPLES.items():
    subset = df_out[df_out['label_multi'] == cls]
    if len(subset) == 0:
        print(f"      ⚠️  Classe {cls} absente")
        continue
    n_actual = min(n, len(subset))
    samples.append(subset.sample(n=n_actual, random_state=42))
    print(f"      {cls:15s} : {n_actual:,} lignes")

df_final = pd.concat(samples, ignore_index=True)
df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n      Total final : {len(df_final):,} lignes")
print("\n      Distribution finale :")
print(df_final['label_multi'].value_counts().to_string())

print("\n[5/5] Sauvegarde...")
os.makedirs('ml/data_prepared', exist_ok=True)
df_final[top_features + ['label_multi']].to_csv(
    'ml/data_prepared/cicids2017_prepared.csv', index=False
)
print("      → ml/data_prepared/cicids2017_prepared.csv")

print("\n" + "=" * 55)
print("  CICIDS2017 prêt — 9 classes ✓")
print("=" * 55)