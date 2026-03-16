"""
prepare_cicids2017_full.py
Extrait Infiltration et WebAttack depuis les fichiers CICIDS2017 par jour
Source : D:\MachineLearningCSV\MachineLearningCSV\MachineLearningCVE\
"""
import pandas as pd
import numpy as np
import glob
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

# ─── Mapping labels CICIDS2017 ────────────────────────────────────────
label_map = {
    'BENIGN': 'Normal', 'Benign': 'Normal', 'benign': 'Normal',
    # WebAttack — toutes les variantes de tiret possibles
    'Web Attack \x96 Brute Force':    'WebAttack',  # Windows-1252 raw
    'Web Attack \x96 XSS':            'WebAttack',
    'Web Attack \x96 Sql Injection':  'WebAttack',
    'Web Attack – Brute Force':        'WebAttack',  # Unicode en-dash
    'Web Attack – XSS':                'WebAttack',
    'Web Attack – Sql Injection':      'WebAttack',
    'Web Attack - Brute Force':        'WebAttack',  # tiret simple
    'Web Attack - XSS':                'WebAttack',
    'Web Attack - Sql Injection':      'WebAttack',
    'Web Attack � Brute Force':   'WebAttack',  # UTF-8 replacement char
    'Web Attack � XSS':           'WebAttack',
    'Web Attack � Sql Injection': 'WebAttack',
    # Infiltration
    'Infiltration': 'Infiltration',
    # DoS (secondaire)
    'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS',
    'Heartbleed': 'DoS',
    # DDoS
    'DDoS': 'DDoS',
    # BruteForce
    'FTP-Patator': 'BruteForce', 'SSH-Patator': 'BruteForce',
    # Botnet
    'Bot': 'Botnet',
    # Probe
    'PortScan': 'Probe',
}

COL_MAP = {
    ' Flow Duration': 'duration', 'Flow Duration': 'duration',
    ' Total Fwd Packets': 'count', 'Total Fwd Packets': 'count',
    'Tot Fwd Pkts': 'count', ' Tot Fwd Pkts': 'count',
    ' Total Backward Packets': 'srv_count',
    'Total Backward Packets': 'srv_count',
    'Total Length of Fwd Packets': 'src_bytes',
    ' Total Length of Fwd Packets': 'src_bytes',
    'TotLen Fwd Pkts': 'src_bytes', ' TotLen Fwd Pkts': 'src_bytes',
    'Total Length of Bwd Packets': 'dst_bytes',
    ' Total Length of Bwd Packets': 'dst_bytes',
    'TotLen Bwd Pkts': 'dst_bytes', ' TotLen Bwd Pkts': 'dst_bytes',
    'SYN Flag Cnt': 'serror_rate', ' SYN Flag Cnt': 'serror_rate',
    'Fwd PSH Flags': 'serror_rate', ' Fwd PSH Flags': 'serror_rate',
    'RST Flag Cnt': 'rerror_rate', ' RST Flag Cnt': 'rerror_rate',
    ' Label': 'label_raw', 'Label': 'label_raw',
}

# Plafonds — diagnostic confirmé :
#   Infiltration : seulement 36 lignes dans tout CICIDS2017 → on skippe
#   WebAttack    : 2,180 lignes dans Thursday-Morning (latin-1)
#   On prend tout le WebAttack disponible
SAMPLES = {
    'WebAttack':  2500,   # tout ce qui est dispo (~2,180)
    'Normal':     5000,   # quelques Normal
}

# ─── CHEMINS ─────────────────────────────────────────────────────────
SOURCE_DIR = r'D:\MachineLearningCSV\MachineLearningCSV\MachineLearningCVE'
OUTPUT_DIR = r'D:\MYLO\ml\data_prepared'

# Fichiers qui nécessitent latin-1 (caractère \x96 dans les labels WebAttack)
LATIN1_FILES = ['Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv']

print("=" * 60)
print("  MYLO — Préparation CICIDS2017 fichiers par jour")
print(f"  Source : {SOURCE_DIR}")
print("  Cible  : Infiltration + WebAttack")
print("=" * 60)

csv_files = glob.glob(os.path.join(SOURCE_DIR, '*.csv'))
if not csv_files:
    print(f"❌  Aucun CSV dans {SOURCE_DIR}"); exit(1)

print(f"\n  {len(csv_files)} fichiers détectés :")
for f in sorted(csv_files):
    size_mb = os.path.getsize(f) / (1024*1024)
    print(f"    • {os.path.basename(f):55s} {size_mb:>7.0f} MB")

def safe(s):
    return pd.to_numeric(s, errors='coerce').fillna(0)

def normalize_label(raw):
    s = str(raw).strip()
    if s in label_map:
        return label_map[s]
    # Essai avec remplacement du tiret Windows
    s2 = s.replace('\x96', '–')
    if s2 in label_map:
        return label_map[s2]
    s3 = s.replace('–', '-')
    if s3 in label_map:
        return label_map[s3]
    return None

def load_and_prepare(filepath):
    fname = os.path.basename(filepath)
    # Forcer latin-1 pour les fichiers avec caractères Windows-1252
    # Vérification sur le basename uniquement (pas le chemin complet)
    enc = 'latin-1' if any(x in fname for x in LATIN1_FILES) else 'utf-8'
    try:
        df = pd.read_csv(filepath, encoding=enc, low_memory=False,
                         on_bad_lines='skip')
    except UnicodeDecodeError:
        df = pd.read_csv(filepath, encoding='latin-1', low_memory=False,
                         on_bad_lines='skip')

    df.columns = df.columns.str.strip()
    df = df.rename(columns={k: v for k, v in COL_MAP.items() if k in df.columns})

    if 'label_raw' not in df.columns:
        lc = next((c for c in df.columns if 'label' in c.lower()), None)
        if lc:
            df = df.rename(columns={lc: 'label_raw'})
        else:
            print(f"    ⚠️  {fname} — pas de colonne label"); return None

    df['label_raw']   = df['label_raw'].astype(str).str.strip()
    df['label_multi'] = df['label_raw'].apply(normalize_label)
    df = df[df['label_multi'].notna()]

    if df.empty:
        return None

    # Afficher distribution
    dist = df['label_multi'].value_counts()
    print(f"\n    {fname} — {len(df):,} lignes après mapping :")
    for cls, cnt in dist.items():
        print(f"      {cls:15s} : {cnt:>8,}")

    # Construire features
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
    return out

# ─── Charger tous les fichiers ────────────────────────────────────────
print(f"\n[1/3] Chargement des fichiers...")
all_dfs = []
for f in sorted(csv_files):
    df_prep = load_and_prepare(f)
    if df_prep is not None:
        all_dfs.append(df_prep)

if not all_dfs:
    print("❌  Aucune donnée chargée"); exit(1)

df_all = pd.concat(all_dfs, ignore_index=True)
print(f"\n\n  Total brut fusionné : {len(df_all):,} lignes")
print("\n  Distribution globale :")
print(df_all['label_multi'].value_counts().to_string())

# ─── Déduplication ────────────────────────────────────────────────────
print(f"\n[2/3] Déduplication...")
before = len(df_all)
df_all = df_all.drop_duplicates(subset=top_features)
print(f"  {before-len(df_all):,} doublons supprimés → {len(df_all):,} lignes")

# ─── Échantillonnage ──────────────────────────────────────────────────
print(f"\n[3/3] Échantillonnage...")
parts = []
for cls, n in SAMPLES.items():
    sub = df_all[df_all['label_multi'] == cls]
    if len(sub) == 0:
        print(f"  ⚠️  '{cls}' absente"); continue
    n_a = min(n, len(sub))
    status = 'complet' if n_a == n else f'tout ({len(sub):,} dispo)'
    parts.append(sub.sample(n=n_a, random_state=42))
    print(f"  {cls:15s} : {n_a:>8,} lignes  ({status})")

df_final = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42)
print(f"\n  Total final : {len(df_final):,} lignes")
print("\n  Distribution finale :")
print(df_final['label_multi'].value_counts().to_string())

os.makedirs(OUTPUT_DIR, exist_ok=True)
out = os.path.join(OUTPUT_DIR, 'cicids2017_infiltration_prepared.csv')
df_final[top_features + ['label_multi']].to_csv(out, index=False)
print(f"\n  → {out}")
print("\n" + "=" * 60)
print("  CICIDS2017 Infiltration + WebAttack prêt ✓")
print("=" * 60)