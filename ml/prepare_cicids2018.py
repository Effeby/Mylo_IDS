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

# ─── Labels EXACTS confirmés par diagnostic ───────────────────────────
# Source : python ml/diagnose_cicids2018.py
#
# 02-14 : FTP-BruteForce, SSH-Bruteforce, Benign
# 02-15 : Benign, DoS attacks-GoldenEye, DoS attacks-Slowloris
# 02-16 : DoS attacks-Hulk, Benign, DoS attacks-SlowHTTPTest
# 02-20 : DDoS attacks-LOIC-HTTP, Benign
# 02-21 : DDOS attack-HOIC, Benign, DDOS attack-LOIC-UDP
# 02-22 : Benign, Brute Force -Web, Brute Force -XSS, SQL Injection
# 02-23 : Benign, Brute Force -Web, Brute Force -XSS, SQL Injection
# 02-28 : Benign, Infilteration (faute), Label (header dupliqué)
# 03-01 : Benign, Infilteration (faute), Label (header dupliqué)
# 03-02 : Bot, Benign

label_map = {
    'Benign':                   'Normal',
    # DoS
    'DoS attacks-GoldenEye':    'DoS',
    'DoS attacks-Slowloris':    'DoS',
    'DoS attacks-SlowHTTPTest': 'DoS',
    'DoS attacks-Hulk':         'DoS',
    # DDoS
    'DDoS attacks-LOIC-HTTP':   'DDoS',
    'DDOS attack-HOIC':         'DDoS',
    'DDOS attack-LOIC-UDP':     'DDoS',
    # BruteForce
    'FTP-BruteForce':           'BruteForce',
    'SSH-Bruteforce':           'BruteForce',
    'Brute Force -Web':         'BruteForce',   # présent 02-22 et 02-23
    'Brute Force -XSS':         'BruteForce',   # présent 02-22 et 02-23
    # WebAttack
    'SQL Injection':            'WebAttack',    # présent 02-22 et 02-23
    # Botnet
    'Bot':                      'Botnet',
    # Infiltration — FAUTE DE FRAPPE OFFICIELLE dans le dataset
    'Infilteration':            'Infiltration', # ← 'e' en trop, c'est voulu
    # À ignorer
    'Label':                    None,           # headers dupliqués dans 02-28/03-01
}

COL_MAP = {
    'Flow Duration': 'duration', ' Flow Duration': 'duration',
    'Tot Fwd Pkts': 'count', ' Tot Fwd Pkts': 'count',
    'Total Fwd Packets': 'count', ' Total Fwd Packets': 'count',
    'Tot Bwd Pkts': 'srv_count', ' Tot Bwd Pkts': 'srv_count',
    'Total Backward Packets': 'srv_count', ' Total Backward Packets': 'srv_count',
    'TotLen Fwd Pkts': 'src_bytes', ' TotLen Fwd Pkts': 'src_bytes',
    'Total Length of Fwd Packets': 'src_bytes',
    'TotLen Bwd Pkts': 'dst_bytes', ' TotLen Bwd Pkts': 'dst_bytes',
    'Total Length of Bwd Packets': 'dst_bytes',
    ' Total Length of Bwd Packets': 'dst_bytes',
    'SYN Flag Cnt': 'serror_rate', ' SYN Flag Cnt': 'serror_rate',
    'RST Flag Cnt': 'rerror_rate', ' RST Flag Cnt': 'rerror_rate',
    'Label': 'label_raw', ' Label': 'label_raw',
}

# Plafonds réalistes basés sur le diagnostic
# WebAttack : ~928 dispo total → on prend tout (pas de plafond)
# Infiltration : ~126k dispo → on en prend 10k
SAMPLES = {
    'Normal':       50000,
    'DoS':          30000,
    'DDoS':         30000,
    'BruteForce':   15000,
    'WebAttack':     1000,   # tout ce qui est dispo (~928)
    'Botnet':        5000,
    'Infiltration': 10000,   # 'Infilteration' → corrigé
}

CHUNK_SIZE  = 100_000
SOURCE_DIR  = r'D:\CSE-CIC-IDS2018'
OUTPUT_DIR  = r'D:\MYLO\ml\data_prepared'

print("=" * 60)
print("  MYLO — Préparation CIC-IDS2018")
print(f"  Source : {SOURCE_DIR}")
print("  Labels exacts confirmés par diagnostic")
print("=" * 60)
print("""
  Rappel labels réels :
    WebAttack   → SQL Injection + Brute Force -Web/-XSS (~928 total)
    Infiltration → 'Infilteration' (faute officielle) (~126k total)
""")

csv_files = glob.glob(os.path.join(SOURCE_DIR, '*.csv'))
if not csv_files:
    print(f"❌  Aucun CSV trouvé dans {SOURCE_DIR}"); exit(1)

def safe(s):
    return pd.to_numeric(s, errors='coerce').fillna(0)

def process_chunk(chunk):
    chunk.columns = chunk.columns.str.strip()
    chunk = chunk.rename(columns={k: v for k, v in COL_MAP.items()
                                   if k in chunk.columns})
    if 'label_raw' not in chunk.columns:
        lc = next((c for c in chunk.columns if 'label' in c.lower()), None)
        if lc is None:
            return None
        chunk = chunk.rename(columns={lc: 'label_raw'})

    chunk['label_raw'] = chunk['label_raw'].astype(str).str.strip()
    chunk['label_multi'] = chunk['label_raw'].map(label_map)
    # Supprimer les lignes non mappées ET les 'Label' (None)
    chunk = chunk[chunk['label_multi'].notna()]
    if chunk.empty:
        return None

    # Déduplication dans le chunk
    dup_cols = [c for c in ['src_bytes','dst_bytes','duration','count','label_raw']
                if c in chunk.columns]
    if dup_cols:
        chunk = chunk.drop_duplicates(subset=dup_cols)

    out = pd.DataFrame()
    out['src_bytes']   = safe(chunk.get('src_bytes',   pd.Series(0, index=chunk.index)))
    out['dst_bytes']   = safe(chunk.get('dst_bytes',   pd.Series(0, index=chunk.index)))
    out['duration']    = safe(chunk.get('duration',    pd.Series(0, index=chunk.index)))
    out['count']       = safe(chunk.get('count',       pd.Series(1, index=chunk.index)))
    out['srv_count']   = safe(chunk.get('srv_count',   pd.Series(0, index=chunk.index)))
    out['serror_rate'] = safe(chunk.get('serror_rate', pd.Series(0, index=chunk.index)))
    out['rerror_rate'] = safe(chunk.get('rerror_rate', pd.Series(0, index=chunk.index)))

    for sc, dc in [
        ('Dst Port','dst_host_srv_count'), (' Dst Port','dst_host_srv_count'),
        ('Flow Pkts/s','dst_host_same_srv_rate'), (' Flow Pkts/s','dst_host_same_srv_rate'),
        ('Flow Byts/s','same_srv_rate'), (' Flow Byts/s','same_srv_rate'),
    ]:
        if sc in chunk.columns:
            out[dc] = safe(chunk[sc])

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

    out['label_multi'] = chunk['label_multi'].values
    out.replace([np.inf, -np.inf], np.nan, inplace=True)
    out.dropna(subset=top_features, inplace=True)
    return out

# ─── Accumulation par classe ──────────────────────────────────────────
buckets       = {cls: [] for cls in SAMPLES}
bucket_counts = {cls: 0  for cls in SAMPLES}

print(f"[1/3] Lecture par chunks de {CHUNK_SIZE:,} lignes...")
print(f"      Plafonds : {SAMPLES}\n")

for f in sorted(csv_files):
    fname   = os.path.basename(f)
    size_mb = os.path.getsize(f) / (1024 * 1024)

    if all(bucket_counts[cls] >= SAMPLES[cls] for cls in SAMPLES):
        print(f"  ⏭  {fname} — tous les plafonds atteints")
        continue

    print(f"  📂 {fname:25s} ({size_mb:.0f} MB)...")
    file_rows = 0

    try:
        for chunk in pd.read_csv(f, encoding='utf-8', low_memory=False,
                                  chunksize=CHUNK_SIZE, on_bad_lines='skip'):
            processed = process_chunk(chunk)
            if processed is None or processed.empty:
                continue

            file_rows += len(chunk)

            for cls in SAMPLES:
                if bucket_counts[cls] >= SAMPLES[cls]:
                    continue
                subset = processed[processed['label_multi'] == cls]
                if subset.empty:
                    continue
                needed = SAMPLES[cls] - bucket_counts[cls]
                to_add = subset.head(needed)
                buckets[cls].append(to_add)
                bucket_counts[cls] += len(to_add)

            filled = sum(1 for cls in SAMPLES
                         if bucket_counts[cls] >= SAMPLES[cls])
            # Afficher toutes les classes en temps reel
            parts_display = []
            for cls in SAMPLES:
                icon = 'v' if bucket_counts[cls] >= SAMPLES[cls] else ' '
                parts_display.append(f"{icon}{cls[:5]}:{bucket_counts[cls]:>5,}")
            status = ' | '.join(parts_display)
            print(f"    {file_rows:>9,} lignes | remplies:{filled}/{len(SAMPLES)} | {status}", end='\r')

            if all(bucket_counts[cls] >= SAMPLES[cls] for cls in SAMPLES):
                break

    except Exception as e:
        print(f"\n    ⚠️  Erreur : {e}")

    print(f"\n     ✓ {fname}")

# ─── Résumé ───────────────────────────────────────────────────────────
print(f"\n[2/3] Résumé collecte :")
for cls in SAMPLES:
    icon = '✅' if bucket_counts[cls] >= SAMPLES[cls] else '⚠️ '
    print(f"  {icon} {cls:15s} : {bucket_counts[cls]:>7,} / {SAMPLES[cls]:,}")

# ─── Assemblage + déduplication ───────────────────────────────────────
print(f"\n[3/3] Assemblage + déduplication + sauvegarde...")
parts = []
for cls in SAMPLES:
    if not buckets[cls]:
        print(f"  ⚠️  {cls} — aucune donnée collectée")
        continue
    df_cls = pd.concat(buckets[cls], ignore_index=True)
    before = len(df_cls)
    df_cls = df_cls.drop_duplicates(subset=top_features)
    after  = len(df_cls)
    if before != after:
        print(f"  🧹 {cls:15s} : {before-after:,} doublons ({before:,}→{after:,})")
    parts.append(df_cls)

df_final = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42)
print(f"\n  Total final : {len(df_final):,} lignes")
print("\n  Distribution finale :")
print(df_final['label_multi'].value_counts().to_string())

os.makedirs(OUTPUT_DIR, exist_ok=True)
out = os.path.join(OUTPUT_DIR, 'cicids2018_prepared.csv')
df_final[top_features + ['label_multi']].to_csv(out, index=False)
print(f"\n  → {out}")
print("\n" + "=" * 60)
print("  CIC-IDS2018 prêt — labels exacts ✓")
print("=" * 60)