"""
prepare_webattack_thursday.py
Extrait les WebAttack du fichier Thursday-Morning-WebAttacks de CICIDS2017
Lance : python ml/prepare_webattack_thursday.py
"""
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

COL_MAP = {
    ' Flow Duration': 'duration', 'Flow Duration': 'duration',
    ' Total Fwd Packets': 'count', 'Total Fwd Packets': 'count',
    ' Total Backward Packets': 'srv_count', 'Total Backward Packets': 'srv_count',
    'Total Length of Fwd Packets': 'src_bytes',
    ' Total Length of Fwd Packets': 'src_bytes',
    'Total Length of Bwd Packets': 'dst_bytes',
    ' Total Length of Bwd Packets': 'dst_bytes',
    'SYN Flag Cnt': 'serror_rate', ' SYN Flag Cnt': 'serror_rate',
    'RST Flag Cnt': 'rerror_rate', ' RST Flag Cnt': 'rerror_rate',
    ' Label': 'label_raw', 'Label': 'label_raw',
}

SOURCE = r'D:\MachineLearningCSV\MachineLearningCSV\MachineLearningCVE\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
OUTPUT_DIR = r'D:\MYLO\ml\data_prepared'

print("=" * 60)
print("  MYLO — WebAttack Thursday CICIDS2017")
print(f"  Source : {SOURCE}")
print("=" * 60)

if not os.path.exists(SOURCE):
    print(f"Introuvable : {SOURCE}"); exit(1)

# ─── Lire en latin-1 OBLIGATOIRE pour ce fichier ─────────────────────
print("\n[1/4] Chargement en latin-1...")
df = pd.read_csv(SOURCE, encoding='latin-1', low_memory=False,
                 on_bad_lines='skip')
df.columns = df.columns.str.strip()
print(f"  {len(df):,} lignes | {len(df.columns)} colonnes")

# ─── Afficher les vrais labels pour vérification ─────────────────────
print("\n[2/4] Labels bruts détectés :")
lc = next((c for c in df.columns if 'label' in c.lower()), None)
if lc is None:
    print("Pas de colonne label !"); exit(1)
df = df.rename(columns={lc: 'label_raw'})
df['label_raw'] = df['label_raw'].astype(str).str.strip()
for v, cnt in df['label_raw'].value_counts().items():
    print(f"  {cnt:>6,}  {repr(v)}")

# ─── Mapping dynamique — on mappe tout ce qui contient "Web Attack" ───
print("\n[3/4] Mapping...")
def map_label(raw):
    s = str(raw).strip()
    if s in ('BENIGN', 'Benign', 'benign'):
        return 'Normal'
    # Capturer toute variante "Web Attack *" quelle que soit l'encodage
    if s.lower().startswith('web attack'):
        return 'WebAttack'
    return None

df['label_multi'] = df['label_raw'].apply(map_label)
df = df[df['label_multi'].notna()]
print(f"  Distribution :")
print(df['label_multi'].value_counts().to_string())

# ─── Construire features ──────────────────────────────────────────────
print("\n[4/4] Construction features + sauvegarde...")
df = df.rename(columns={k: v for k, v in COL_MAP.items() if k in df.columns})

def safe(s): return pd.to_numeric(s, errors='coerce').fillna(0)

out = pd.DataFrame()
out['src_bytes']   = safe(df.get('src_bytes',   pd.Series(0, index=df.index)))
out['dst_bytes']   = safe(df.get('dst_bytes',   pd.Series(0, index=df.index)))
out['duration']    = safe(df.get('duration',    pd.Series(0, index=df.index)))
out['count']       = safe(df.get('count',       pd.Series(1, index=df.index)))
out['srv_count']   = safe(df.get('srv_count',   pd.Series(0, index=df.index)))
out['serror_rate'] = safe(df.get('serror_rate', pd.Series(0, index=df.index)))
out['rerror_rate'] = safe(df.get('rerror_rate', pd.Series(0, index=df.index)))

for sc, dc in [
    ('Dst Port','dst_host_srv_count'), (' Dst Port','dst_host_srv_count'),
    ('Flow Pkts/s','dst_host_same_srv_rate'), (' Flow Pkts/s','dst_host_same_srv_rate'),
    ('Flow Byts/s','same_srv_rate'), (' Flow Byts/s','same_srv_rate'),
]:
    if sc in df.columns:
        out[dc] = safe(df[sc])

out['bytes_ratio']                 = out['src_bytes'] / (out['dst_bytes'] + 1)
out['bytes_per_packet']            = out['src_bytes'] / out['count'].clip(lower=1)
out['serror_diff']                 = out['serror_rate'] - out['rerror_rate']
out['dst_host_serror_rate']        = out['serror_rate']
out['srv_serror_rate']             = out['serror_rate']
out['dst_host_rerror_rate']        = out['rerror_rate']
out['dst_host_count']              = out['count'].clip(upper=255)
out['dst_host_same_src_port_rate'] = 0.0
out['dst_host_diff_srv_rate']      = 0.0
out['diff_srv_rate']               = 0.0
out['logged_in']                   = 0
out['flag']                        = 10
out['protocol_type']               = 2

for col in top_features:
    if col not in out.columns:
        out[col] = 0.0

out['label_multi'] = df['label_multi'].values
out.replace([np.inf, -np.inf], np.nan, inplace=True)
out.dropna(subset=top_features, inplace=True)

# Déduplication
before = len(out)
out = out.drop_duplicates(subset=top_features)
print(f"  Dédup : {before-len(out):,} supprimés → {len(out):,} lignes")
print(f"\n  Distribution finale :")
print(out['label_multi'].value_counts().to_string())

os.makedirs(OUTPUT_DIR, exist_ok=True)
path = os.path.join(OUTPUT_DIR, 'webattack_thursday_prepared.csv')
out[top_features + ['label_multi']].to_csv(path, index=False)
print(f"\n  → {path}")
print("\n" + "=" * 60)
print("  WebAttack Thursday prêt ✓")
print("=" * 60)