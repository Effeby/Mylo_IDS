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

label_map = {
    '-': 'Normal', ' -': 'Normal', 'Normal': 'Normal',
    'normal': 'Normal', '': 'Normal', 'nan': 'Normal',
    'DoS': 'DoS', 'dos': 'DoS',
    'Reconnaissance': 'Probe', 'reconnaissance': 'Probe',
    'Fuzzers': 'Probe',  'fuzzers': 'Probe',
    'Backdoors': 'R2L',  'backdoors': 'R2L', 'Backdoor': 'R2L',
    'Exploits': 'R2L',   'exploits': 'R2L',
    'Shellcode': 'U2R',  'shellcode': 'U2R',
    'Worms': 'U2R',      'worms': 'U2R',
    'Analysis': 'WebAttack', 'analysis': 'WebAttack',
    'Generic': 'DDoS',   'generic': 'DDoS',
}

COL_MAP = {
    'sbytes': 'src_bytes',  'dbytes': 'dst_bytes',
    'dur':    'duration',
    'spkts':  'count',      'dpkts':  'srv_count',
    'synack': 'serror_rate','ackdat': 'rerror_rate',
    'dload':  'dst_host_srv_count',
    'sload':  'same_srv_rate',
    'dinpkt': 'dst_host_same_srv_rate',
    'ct_srv_src':     'dst_host_count',
    'ct_dst_src_ltm': 'dst_host_same_src_port_rate',
    'ct_srv_dst':     'diff_srv_rate',
    'is_ftp_login':   'logged_in',
}
PROTO_MAP = {'tcp': 2, 'udp': 1, 'icmp': 0, 'arp': 3, 'ospf': 4}

SAMPLES = {
    'Normal':    40000,
    'DoS':       15000,
    'DDoS':      10000,
    'Probe':     20000,
    'R2L':       15000,
    'U2R':        5000,
    'WebAttack':  5000,
}

SOURCE_DIR = r'D:\UNSW-NB15'
OUTPUT_DIR = r'D:\MYLO\ml\data_prepared'

print("=" * 60)
print("  MYLO — Préparation UNSW-NB15")
print(f"  Source : {SOURCE_DIR}")
print("=" * 60)

# ══════════════════════════════════════════════════════════════════
#  CHOIX DE LA SOURCE — priorité aux fichiers training/testing set
#  qui sont déjà propres et labelisés avec attack_cat.
#  Les fichiers _1 à _4 sont les MÊMES données sans headers →
#  on NE les charge PAS en même temps pour éviter les doublons.
# ══════════════════════════════════════════════════════════════════
train_path = os.path.join(SOURCE_DIR, 'UNSW_NB15_training-set.csv')
test_path  = os.path.join(SOURCE_DIR, 'UNSW_NB15_testing-set.csv')

if not os.path.exists(train_path) or not os.path.exists(test_path):
    print(f"❌  Fichiers introuvables :")
    print(f"    {train_path}")
    print(f"    {test_path}")
    exit(1)

print(f"\n[1/5] Chargement (training-set + testing-set uniquement)...")
print(f"      ℹ️  Les fichiers UNSW-NB15_1..4.csv sont ignorés volontairement")
print(f"         (mêmes données que training/testing → évite les doublons)\n")

dfs = []
for path, name in [(train_path, 'UNSW_NB15_training-set.csv'),
                   (test_path,  'UNSW_NB15_testing-set.csv')]:
    df_tmp = pd.read_csv(path, low_memory=False)
    df_tmp.columns = df_tmp.columns.str.strip().str.lower()
    size_mb = os.path.getsize(path) / (1024 * 1024)
    print(f"  ✓ {name:35s}  {len(df_tmp):>8,} lignes  ({size_mb:.0f} MB)")
    dfs.append(df_tmp)

df = pd.concat(dfs, ignore_index=True)
print(f"\n  Total brut : {len(df):,} lignes  |  Colonnes : {len(df.columns)}")

# ─── Déduplication immédiate ──────────────────────────────────────────
print("\n[2/5] Déduplication...")
before = len(df)
# Colonnes clés pour détecter les vrais doublons
dup_keys = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'dur', 'sbytes', 'dbytes']
dup_keys_available = [c for c in dup_keys if c in df.columns]
if dup_keys_available:
    df = df.drop_duplicates(subset=dup_keys_available)
else:
    df = df.drop_duplicates()
after = len(df)
print(f"  Avant : {before:,}  |  Après : {after:,}  |  Supprimés : {before-after:,}")

# ─── Labels ───────────────────────────────────────────────────────────
print("\n[3/5] Mapping des labels...")
if 'attack_cat' not in df.columns:
    print("❌  Colonne attack_cat introuvable.")
    print("    Colonnes :", df.columns.tolist()); exit(1)

df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
df['attack_cat'] = df['attack_cat'].replace({'nan': '-', 'NaN': '-', '': '-'})

print("  Valeurs attack_cat originales :")
print(df['attack_cat'].value_counts().to_string())

df['label_multi'] = df['attack_cat'].map(label_map)

# Fallback pour les lignes sans mapping (label binaire 0 = Normal)
if 'label' in df.columns:
    mask = df['label_multi'].isna()
    df.loc[mask & (pd.to_numeric(df['label'], errors='coerce') == 0), 'label_multi'] = 'Normal'

not_mapped = df['label_multi'].isna().sum()
if not_mapped > 0:
    print(f"\n  ⚠️  {not_mapped:,} lignes sans mapping → supprimées")
    unmapped_vals = df[df['label_multi'].isna()]['attack_cat'].value_counts()
    print(f"     Valeurs non mappées : {unmapped_vals.to_dict()}")

df = df[df['label_multi'].notna()]
print(f"\n  Distribution après mapping :")
print(df['label_multi'].value_counts().to_string())

# ─── Features ─────────────────────────────────────────────────────────
print("\n[4/5] Construction des features...")

def safe(s):
    return pd.to_numeric(s, errors='coerce').fillna(0)

df = df.rename(columns={k: v for k, v in COL_MAP.items() if k in df.columns})

df_out = pd.DataFrame()
for feat in ['src_bytes','dst_bytes','duration','count','srv_count',
             'serror_rate','rerror_rate','dst_host_srv_count',
             'same_srv_rate','dst_host_same_srv_rate','dst_host_count',
             'dst_host_same_src_port_rate','diff_srv_rate','logged_in']:
    df_out[feat] = safe(df.get(feat, pd.Series(0, index=df.index)))

# Protocole texte → numérique
if 'proto' in df.columns:
    df_out['protocol_type'] = df['proto'].astype(str).str.lower().map(PROTO_MAP).fillna(2)
else:
    df_out['protocol_type'] = 2

# Features UNSW supplémentaires disponibles
if 'ct_state_ttl' in df.columns:
    df_out['dst_host_same_src_port_rate'] = safe(df['ct_state_ttl']) / 10
if 'tcprtt' in df.columns:
    df_out['dst_host_diff_srv_rate'] = safe(df['tcprtt'])

# Features dérivées
df_out['bytes_ratio']          = df_out['src_bytes'] / (df_out['dst_bytes'] + 1)
df_out['bytes_per_packet']     = df_out['src_bytes'] / df_out['count'].clip(lower=1)
df_out['serror_diff']          = df_out['serror_rate'] - df_out['rerror_rate']
df_out['dst_host_serror_rate'] = df_out['serror_rate']
df_out['srv_serror_rate']      = df_out['serror_rate']
df_out['dst_host_rerror_rate'] = df_out['rerror_rate']
df_out['flag']                 = 10

for col in top_features:
    if col not in df_out.columns:
        df_out[col] = 0.0

df_out['label_multi'] = df['label_multi'].values

# Nettoyage inf/NaN
df_out.replace([np.inf, -np.inf], np.nan, inplace=True)
df_out.dropna(subset=top_features, inplace=True)
print(f"  Lignes après nettoyage : {len(df_out):,}")

# Déduplication sur les features finales
before = len(df_out)
df_out = df_out.drop_duplicates(subset=top_features)
after  = len(df_out)
if before != after:
    print(f"  🧹 Déduplication features : {before-after:,} supprimés ({before:,} → {after:,})")

# ─── Échantillonnage ──────────────────────────────────────────────────
print("\n[5/5] Échantillonnage équilibré...")
samples = []
for cls, n in SAMPLES.items():
    sub = df_out[df_out['label_multi'] == cls]
    if len(sub) == 0:
        print(f"  ⚠️  '{cls}' absente"); continue
    n_a = min(n, len(sub))
    status = 'complet' if n_a == n else f'tout ({len(sub):,} dispo)'
    samples.append(sub.sample(n=n_a, random_state=42))
    print(f"  {cls:12s} : {n_a:>8,} lignes  ({status})")

df_final = pd.concat(samples, ignore_index=True).sample(frac=1, random_state=42)
print(f"\n  Total final : {len(df_final):,} lignes")
print(df_final['label_multi'].value_counts().to_string())

os.makedirs(OUTPUT_DIR, exist_ok=True)
out = os.path.join(OUTPUT_DIR, 'unswnb15_prepared.csv')
df_final[top_features + ['label_multi']].to_csv(out, index=False)
print(f"\n  → {out}")
print("\n" + "=" * 60)
print("  UNSW-NB15 prêt — sans doublons ✓")
print("=" * 60)