import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
import json

# ─── COLONNES NSL-KDD ─────────────────────────────────────────────────
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

top_features = [
    "src_bytes", "dst_bytes", "same_srv_rate", "dst_host_srv_count",
    "dst_host_same_srv_rate", "flag", "logged_in", "diff_srv_rate",
    "protocol_type", "count", "dst_host_count", "serror_rate",
    "dst_host_serror_rate", "srv_serror_rate", "dst_host_same_src_port_rate",
    "rerror_rate", "srv_count", "dst_host_rerror_rate",
    "dst_host_diff_srv_rate", "duration",
    "bytes_ratio", "bytes_per_packet", "serror_diff",
]

# ─── Thresholds finaux — meilleure version (90.85% accuracy) ─────────
# R2L=0.720, WebAttack=0.795, Infiltration=0.517
# U2R restera faible (limite fondamentale du dataset)
# Le tuning des thresholds ne peut pas résoudre U2R/Infiltration
# → solution = plus de données réelles pour ces classes
CLASS_THRESHOLDS = {
    "Normal":       0.40,
    "DoS":          0.40,
    "DDoS":         0.35,
    "Probe":        0.40,
    "R2L":          0.15,
    "U2R":          0.10,
    "BruteForce":   0.20,
    "WebAttack":    0.25,
    "Botnet":       0.15,
    "Infiltration": 0.10,
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
print("  Mylo IPS — XGBoost 9 Classes  (v3)")
print("  Test set stratifié sur toutes les sources")
print("  Lancer depuis : D:\\MYLO\\")
print("=" * 60)

os.makedirs("ml/models",  exist_ok=True)
os.makedirs("ml/outputs", exist_ok=True)

# ══════════════════════════════════════════════════════════════════════
#  CHARGEMENT DE TOUTES LES SOURCES
# ══════════════════════════════════════════════════════════════════════
all_X, all_y = [], []

# ─── NSL-KDD (train + test fusionnés) ────────────────────────────────
print("\n[1/7] NSL-KDD...")
train_kdd = pd.read_csv("ml/KDDTrain+.txt", names=columns)
test_kdd  = pd.read_csv("ml/KDDTest+.txt",  names=columns)
kdd_all   = pd.concat([train_kdd, test_kdd], ignore_index=True)

kdd_all["label_multi"] = kdd_all["attack_type"].apply(
    lambda x: attack_map.get(x.strip(), "Other"))
kdd_all = kdd_all[kdd_all["label_multi"] != "Other"]

encoders = {}
for col in ["protocol_type", "service", "flag"]:
    le = LabelEncoder()
    kdd_all[col] = le.fit_transform(kdd_all[col])
    encoders[col] = le
joblib.dump(encoders, "ml/models/encoders.pkl")

kdd_all = add_features(kdd_all)
all_X.append(kdd_all[top_features])
all_y.append(kdd_all["label_multi"])
print(f"  {len(kdd_all):,} lignes")
print(kdd_all["label_multi"].value_counts().to_string())

# ─── CICIDS2017 ───────────────────────────────────────────────────────
print("\n[2/7] CICIDS2017...")
df = pd.read_csv("ml/data_prepared/cicids2017_prepared.csv")
df = ensure_features(df)
all_X.append(df[top_features])
all_y.append(df["label_multi"])
print(f"  {len(df):,} lignes")
print(df["label_multi"].value_counts().to_string())

# ─── NIDS ─────────────────────────────────────────────────────────────
print("\n[3/7] NIDS...")
df = pd.read_csv("ml/data_prepared/nids_prepared.csv")
df = ensure_features(df)
all_X.append(df[top_features])
all_y.append(df["label_multi"])
print(f"  {len(df):,} lignes")
print(df["label_multi"].value_counts().to_string())

# ─── CIC-IDS2018 ──────────────────────────────────────────────────────
print("\n[4/7] CIC-IDS2018...")
p = "ml/data_prepared/cicids2018_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    all_X.append(df[top_features])
    all_y.append(df["label_multi"])
    print(f"  {len(df):,} lignes")
    print(df["label_multi"].value_counts().to_string())
else:
    print("  ⚠️  Manquant — lance prepare_cicids2018.py")

# ─── DDoS Friday ──────────────────────────────────────────────────────
print("\n[5/7] DDoS Friday...")
p = "ml/data_prepared/cicddos2019_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    all_X.append(df[top_features])
    all_y.append(df["label_multi"])
    print(f"  {len(df):,} lignes")
    print(df["label_multi"].value_counts().to_string())
else:
    print("  ⚠️  Manquant — lance prepare_cicddos2019.py")

# ─── UNSW-NB15 ────────────────────────────────────────────────────────
print("\n[6/7] UNSW-NB15...")
p = "ml/data_prepared/unswnb15_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    all_X.append(df[top_features])
    all_y.append(df["label_multi"])
    print(f"  {len(df):,} lignes")
    print(df["label_multi"].value_counts().to_string())
else:
    print("  ⚠️  Manquant — lance prepare_unswnb15.py")

# ─── WebAttack HTTP (HTTPParams + CSIC) ───────────────────────────────
print("\n[7/9] WebAttack HTTP (HTTPParams + CSIC)...")
p = "ml/data_prepared/webattack_http_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    all_X.append(df[top_features])
    all_y.append(df["label_multi"])
    print(f"  {len(df):,} lignes")
    print(df["label_multi"].value_counts().to_string())
else:
    print("  ⚠️  Manquant — lance prepare_webattack_http.py")

# ─── KDD99 FULL (R2L + U2R renforcés) ────────────────────────────────
print("\n[8/9] KDD99 FULL (R2L + U2R)...")
p = "ml/data_prepared/kdd99full_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    all_X.append(df[top_features])
    all_y.append(df["label_multi"])
    print(f"  {len(df):,} lignes")
    print(df["label_multi"].value_counts().to_string())
else:
    print("  ⚠️  Manquant — lance prepare_kdd99full.py")

# ─── WebAttack Thursday CICIDS2017 ──────────────────────────────────
print("\n[9/9] WebAttack Thursday CICIDS2017...")
p = "ml/data_prepared/webattack_thursday_prepared.csv"
if os.path.exists(p):
    df = pd.read_csv(p)
    df = ensure_features(df)
    all_X.append(df[top_features])
    all_y.append(df["label_multi"])
    print(f"  {len(df):,} lignes")
    print(df["label_multi"].value_counts().to_string())
else:
    print("  ⚠️  Manquant — lance prepare_webattack_thursday.py")

# ══════════════════════════════════════════════════════════════════════
#  FUSION + NETTOYAGE
# ══════════════════════════════════════════════════════════════════════
print("\n[10/10] Fusion + nettoyage global...")
X_all = pd.concat(all_X, ignore_index=True)
y_all = pd.concat(all_y, ignore_index=True)
X_all = X_all.replace([np.inf, -np.inf], np.nan).fillna(0)

print(f"\n  Total fusionné : {len(X_all):,} lignes")
print("\n  Distribution toutes sources :")
print(y_all.value_counts().to_string())

# ══════════════════════════════════════════════════════════════════════
#  SPLIT TRAIN / TEST stratifié — LE FIX PRINCIPAL
#  Avant : test = NSL-KDD uniquement → Botnet/DDoS/BruteForce absents
#  Maintenant : 20% de chaque source dans le test
# ══════════════════════════════════════════════════════════════════════
print("\n─── Split Train/Test 80/20 stratifié ───────────────────")
X_train, X_test, y_train, y_test = train_test_split(
    X_all, y_all,
    test_size=0.20,
    random_state=42,
    stratify=y_all
)
print(f"  Train : {len(X_train):,}  |  Test : {len(X_test):,}")
print("\n  Toutes les classes présentes dans le test :")
print(y_test.value_counts().to_string())

# ══════════════════════════════════════════════════════════════════════
#  SMOTE — train uniquement, jamais sur le test
# ══════════════════════════════════════════════════════════════════════
print("\n─── SMOTE (train uniquement) ────────────────────────────")
counts_train = y_train.value_counts()
smote_targets = {}
for cls, cnt in counts_train.items():
    if cnt < 8000:
        smote_targets[cls] = int(max(cnt * 4, 5000))

if smote_targets:
    print(f"  Classes augmentées :")
    for cls, t in smote_targets.items():
        print(f"    {cls:15s} : {counts_train[cls]:>6,} → {t:>6,}")
    smote = SMOTE(sampling_strategy=smote_targets, random_state=42, k_neighbors=3)
    X_sm, y_sm = smote.fit_resample(X_train, y_train)
else:
    X_sm, y_sm = X_train, y_train
    print("  Aucun SMOTE nécessaire")

print(f"\n  Distribution train après SMOTE :")
print(pd.Series(y_sm).value_counts().to_string())

# ══════════════════════════════════════════════════════════════════════
#  ENCODAGE
# ══════════════════════════════════════════════════════════════════════
label_encoder  = LabelEncoder()
y_train_enc    = label_encoder.fit_transform(y_sm)
y_test_enc     = label_encoder.transform(y_test)
y_bin_train    = (pd.Series(y_sm) != "Normal").astype(int).values
y_bin_test     = (y_test != "Normal").astype(int).values
print(f"\n  Classes : {list(label_encoder.classes_)}")

# ══════════════════════════════════════════════════════════════════════
#  MODÈLE BINAIRE
# ══════════════════════════════════════════════════════════════════════
print("\n─── XGBoost Binaire ─────────────────────────────────────")
neg = (y_bin_train == 0).sum()
pos = (y_bin_train == 1).sum()
model_binary = xgb.XGBClassifier(
    objective="binary:logistic", eval_metric="logloss",
    n_estimators=300, max_depth=7, learning_rate=0.1,
    scale_pos_weight=neg / pos,
    random_state=42, n_jobs=-1, verbosity=0
)
model_binary.fit(X_sm, y_bin_train)
y_pred_bin = (model_binary.predict_proba(X_test)[:, 1] >= 0.30).astype(int)

# ══════════════════════════════════════════════════════════════════════
#  MODÈLE MULTI-CLASSES
# ══════════════════════════════════════════════════════════════════════
print("─── XGBoost Multi-Classes ───────────────────────────────")
model_multi = xgb.XGBClassifier(
    objective="multi:softprob",
    num_class=len(label_encoder.classes_),
    eval_metric="mlogloss",
    n_estimators=300, max_depth=7, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    random_state=42, n_jobs=-1, verbosity=0
)
model_multi.fit(X_sm, y_train_enc)

y_proba_multi  = model_multi.predict_proba(X_test)
classes        = label_encoder.classes_
y_pred_encoded = [
    np.argmax([p / CLASS_THRESHOLDS.get(cls, 0.40)
               for cls, p in zip(classes, probs)])
    for probs in y_proba_multi
]
y_pred_multi = label_encoder.inverse_transform(np.array(y_pred_encoded))

# ══════════════════════════════════════════════════════════════════════
#  RÉSULTATS
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("  RÉSULTATS — BINAIRE")
print("=" * 60)
acc_bin = accuracy_score(y_bin_test, y_pred_bin)
print(f"  Accuracy : {acc_bin*100:.2f}%")
print(classification_report(y_bin_test, y_pred_bin,
      target_names=["Normal", "Attaque"], digits=4))

print("=" * 60)
print("  RÉSULTATS — MULTI-CLASSES (9 classes)")
print("=" * 60)
acc_multi = accuracy_score(y_test, y_pred_multi)
print(f"  Accuracy : {acc_multi*100:.2f}%")
print(classification_report(y_test, y_pred_multi,
      labels=sorted(label_encoder.classes_),
      target_names=sorted(label_encoder.classes_),
      zero_division=0, digits=4))

# ─── Diagnostic F1 par classe ─────────────────────────────────────────
print("─── Diagnostic F1 par classe ────────────────────────────")
f1s = f1_score(y_test, y_pred_multi, average=None,
               labels=label_encoder.classes_, zero_division=0)
for cls, f1 in sorted(zip(label_encoder.classes_, f1s), key=lambda x: x[1]):
    icon = "✅" if f1 >= 0.70 else ("⚠️ " if f1 >= 0.40 else "🔴")
    print(f"  {icon} {cls:15s} F1 = {f1:.3f}")

# ══════════════════════════════════════════════════════════════════════
#  GRAPHIQUES
# ══════════════════════════════════════════════════════════════════════
# Confusion binaire
cm = confusion_matrix(y_bin_test, y_pred_bin)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Normal", "Attaque"],
            yticklabels=["Normal", "Attaque"])
plt.title(f"Mylo — Binaire  acc={acc_bin*100:.1f}%")
plt.tight_layout()
plt.savefig("ml/outputs/confusion_binary_9cls.png")
plt.close()

# Confusion multi-classes
present = sorted(set(y_test.values))
cm_m = confusion_matrix(y_test, y_pred_multi, labels=present)
plt.figure(figsize=(11, 9))
sns.heatmap(cm_m, annot=True, fmt="d", cmap="Blues",
            xticklabels=present, yticklabels=present)
plt.title(f"Mylo — Multi-Classes  acc={acc_multi*100:.1f}%")
plt.tight_layout()
plt.savefig("ml/outputs/confusion_multiclass_9cls.png")
plt.close()

# Feature importance
imp = pd.Series(model_binary.feature_importances_, index=top_features)
plt.figure(figsize=(8, 7))
imp.nlargest(15).sort_values().plot(kind="barh", color="steelblue")
plt.title("Mylo IPS — Feature Importance")
plt.tight_layout()
plt.savefig("ml/outputs/feature_importance_9cls.png")
plt.close()

# F1 par classe
f1_series = pd.Series(dict(zip(label_encoder.classes_, f1s))).sort_values()
colors = ["#e74c3c" if v < 0.40 else "#f39c12" if v < 0.70 else "#2ecc71"
          for v in f1_series]
plt.figure(figsize=(9, 5))
f1_series.plot(kind="barh", color=colors)
plt.axvline(x=0.70, color='gray', linestyle='--', alpha=0.7)
plt.title("Mylo IPS — F1 par classe (vert ≥ 0.70)")
plt.tight_layout()
plt.savefig("ml/outputs/f1_par_classe.png")
plt.close()

print("\n  Graphiques → ml/outputs/")

# ══════════════════════════════════════════════════════════════════════
#  SAUVEGARDE
# ══════════════════════════════════════════════════════════════════════
joblib.dump(model_binary,     "ml/models/mylo_xgb_binary.pkl")
joblib.dump(model_multi,      "ml/models/mylo_xgb_multiclass.pkl")
joblib.dump(top_features,     "ml/models/xgb_features.pkl")
joblib.dump(label_encoder,    "ml/models/label_encoder.pkl")
joblib.dump(CLASS_THRESHOLDS, "ml/models/class_thresholds.pkl")

print("\n  Modèles sauvegardés :")
print("  → ml/models/mylo_xgb_binary.pkl")
print("  → ml/models/mylo_xgb_multiclass.pkl")
print("  → ml/models/xgb_features.pkl")
print("  → ml/models/label_encoder.pkl")
print("  → ml/models/class_thresholds.pkl")
print("\n" + "=" * 60)
print("  Mylo IPS — 8 datasets — 9 classes — test honnête ✓")
print("=" * 60)



metrics = {
    "accuracy": round(float(acc_multi) * 100, 2),
    "f1_score": round(float(f1_score(y_test, y_pred_multi, average='weighted', zero_division=0)), 4),
    "classes": list(label_encoder.classes_),
    "training_date": str(date.today()),
    "total_samples": int(len(X_train)),
    "river_updates": 0,  # mis à jour par River à chaque prédiction
}

out_path = os.path.join(os.path.dirname(__file__), "outputs/model_metrics.json")
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w") as f:
    json.dump(metrics, f, indent=2)
print(f"[Mylo] Métriques sauvegardées → {out_path}")