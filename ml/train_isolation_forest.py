"""
Mylo IPS — Entraînement Isolation Forest (détection zero-day)
Entraîné uniquement sur le trafic Normal pour détecter les anomalies inédites.
Lancer depuis : D:\\MYLO\\
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# ─── MÊMES FEATURES QUE XGBoost ──────────────────────────────────────
top_features = [
    "src_bytes", "dst_bytes", "same_srv_rate", "dst_host_srv_count",
    "dst_host_same_srv_rate", "flag", "logged_in", "diff_srv_rate",
    "protocol_type", "count", "dst_host_count", "serror_rate",
    "dst_host_serror_rate", "srv_serror_rate", "dst_host_same_src_port_rate",
    "rerror_rate", "srv_count", "dst_host_rerror_rate",
    "dst_host_diff_srv_rate", "duration",
    "bytes_ratio", "bytes_per_packet", "serror_diff",
]

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "difficulty"
]

attack_map = {
    "normal": "Normal",
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "mailbomb": "DoS",
    "apache2": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L", "warezclient": "R2L",
    "warezmaster": "R2L", "sendmail": "R2L", "named": "R2L",
    "snmpgetattack": "R2L", "snmpguess": "R2L", "xlock": "R2L",
    "xsnoop": "R2L", "httptunnel": "R2L", "worm": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}

def add_features(df):
    df = df.copy()
    df["bytes_ratio"]      = df["src_bytes"] / (df["dst_bytes"] + 1)
    df["bytes_per_packet"] = df["src_bytes"] / (df["count"] + 1)
    df["serror_diff"]      = df["serror_rate"] - df["rerror_rate"]
    return df

def ensure_features(df):
    for col in top_features:
        if col not in df.columns:
            df[col] = 0.0
    return df

print("=" * 60)
print("  Mylo IPS — Isolation Forest (détection zero-day)")
print("=" * 60)

os.makedirs("ml/models", exist_ok=True)
normal_frames = []

# ─── 1. NSL-KDD ───────────────────────────────────────────────────────
print("\n[1/7] NSL-KDD...")
encoders = joblib.load("ml/models/encoders.pkl")
train_kdd = pd.read_csv("ml/KDDTrain+.txt", names=columns)
test_kdd  = pd.read_csv("ml/KDDTest+.txt",  names=columns)
kdd_all   = pd.concat([train_kdd, test_kdd], ignore_index=True)
kdd_all["label_multi"] = kdd_all["attack_type"].apply(
    lambda x: attack_map.get(x.strip(), "Other"))
for col in ["protocol_type", "service", "flag"]:
    le = encoders[col]
    kdd_all[col] = kdd_all[col].apply(
        lambda x: le.transform([x])[0] if x in le.classes_ else 0)
kdd_all = add_features(kdd_all)
normal_kdd = kdd_all[kdd_all["label_multi"] == "Normal"][top_features]
normal_frames.append(normal_kdd)
print(f"  Normal : {len(normal_kdd):,} lignes")

# ─── 2. CICIDS2017 ────────────────────────────────────────────────────
print("\n[2/7] CICIDS2017...")
p = "ml/data_prepared/cicids2017_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    normal = df[df["label_multi"] == "Normal"][top_features]
    normal_frames.append(normal)
    print(f"  Normal : {len(normal):,} lignes")
else:
    print("  ⚠️  Manquant")

# ─── 3. NIDS ──────────────────────────────────────────────────────────
print("\n[3/7] NIDS...")
p = "ml/data_prepared/nids_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    normal = df[df["label_multi"] == "Normal"][top_features]
    normal_frames.append(normal)
    print(f"  Normal : {len(normal):,} lignes")
else:
    print("  ⚠️  Manquant")

# ─── 4. CIC-IDS2018 ───────────────────────────────────────────────────
print("\n[4/7] CIC-IDS2018...")
p = "ml/data_prepared/cicids2018_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    normal = df[df["label_multi"] == "Normal"][top_features]
    normal_frames.append(normal)
    print(f"  Normal : {len(normal):,} lignes")
else:
    print("  ⚠️  Manquant")

# ─── 5. CICDDoS2019 ───────────────────────────────────────────────────
print("\n[5/7] CICDDoS2019...")
p = "ml/data_prepared/cicddos2019_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    normal = df[df["label_multi"] == "Normal"][top_features]
    normal_frames.append(normal)
    print(f"  Normal : {len(normal):,} lignes")
else:
    print("  ⚠️  Manquant")

# ─── 6. UNSW-NB15 ─────────────────────────────────────────────────────
print("\n[6/7] UNSW-NB15...")
p = "ml/data_prepared/unswnb15_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    normal = df[df["label_multi"] == "Normal"][top_features]
    normal_frames.append(normal)
    print(f"  Normal : {len(normal):,} lignes")
else:
    print("  ⚠️  Manquant")

# ─── 7. WebAttack Thursday ────────────────────────────────────────────
print("\n[7/7] WebAttack Thursday...")
p = "ml/data_prepared/webattack_thursday_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    normal = df[df["label_multi"] == "Normal"][top_features]
    normal_frames.append(normal)
    print(f"  Normal : {len(normal):,} lignes")
else:
    print("  ⚠️  Manquant")

# ─── FUSION ───────────────────────────────────────────────────────────
print("\n─── Fusion données normales ─────────────────────────────")
X_normal = pd.concat(normal_frames, ignore_index=True)
X_normal = X_normal.replace([np.inf, -np.inf], np.nan).fillna(0)
print(f"  Total trafic Normal : {len(X_normal):,} lignes")

# Sous-échantillonnage si trop grand (IF ralentit sur >500k lignes)
if len(X_normal) > 300_000:
    X_normal = X_normal.sample(n=300_000, random_state=42)
    print(f"  Sous-échantillonné à 300 000 lignes pour performance")

# ─── ENTRAÎNEMENT ─────────────────────────────────────────────────────
print("\n─── Entraînement Isolation Forest ───────────────────────")
print("  contamination=0.05 → 5% du trafic peut être anomalie")
print("  n_estimators=200, random_state=42")

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,   # 5% de trafic "anormal" attendu
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
    verbose=1,
)
iso_forest.fit(X_normal)

# ─── VALIDATION RAPIDE ────────────────────────────────────────────────
print("\n─── Validation rapide ───────────────────────────────────")
scores = iso_forest.score_samples(X_normal.head(10000))
preds  = iso_forest.predict(X_normal.head(10000))
anomalies = (preds == -1).sum()
print(f"  Sur 10 000 échantillons normaux :")
print(f"  → {anomalies} classés anomalie ({anomalies/100:.1f}%) — attendu ~5%")
print(f"  → Score moyen : {scores.mean():.4f}")
print(f"  → Score min   : {scores.min():.4f}")
print(f"  → Score max   : {scores.max():.4f}")

# ─── SAUVEGARDE ───────────────────────────────────────────────────────
joblib.dump(iso_forest, "ml/models/mylo_isolation_forest.pkl")
print("\n  ✓ ml/models/mylo_isolation_forest.pkl")
print("\n" + "=" * 60)
print("  Isolation Forest entraîné avec succès ✓")
print("=" * 60)