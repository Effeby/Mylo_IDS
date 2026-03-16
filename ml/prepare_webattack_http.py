"""
prepare_webattack_http.py
Transforme HTTPParams + CSIC (datasets texte HTTP) en features numériques
compatibles avec top_features de Mylo.

Stratégie : extraire des signaux statistiques et lexicaux du payload/URL
qui discriminent les attaques web (SQLi, XSS, path traversal, cmdi).
"""
import pandas as pd
import numpy as np
import re
import os
import glob

# ─── MÊME top_features que train_xgb.py ──────────────────────────────
top_features = [
    "src_bytes", "dst_bytes", "same_srv_rate", "dst_host_srv_count",
    "dst_host_same_srv_rate", "flag", "logged_in", "diff_srv_rate",
    "protocol_type", "count", "dst_host_count", "serror_rate",
    "dst_host_serror_rate", "srv_serror_rate", "dst_host_same_src_port_rate",
    "rerror_rate", "srv_count", "dst_host_rerror_rate",
    "dst_host_diff_srv_rate", "duration",
    "bytes_ratio", "bytes_per_packet", "serror_diff",
]

# ─── Patterns SQLi / XSS / traversal / cmdi ───────────────────────────
SQLI_PATTERNS = re.compile(
    r"(select|union|insert|update|delete|drop|alter|exec|execute|"
    r"sleep|benchmark|waitfor|cast|convert|char\(|0x[0-9a-f]+|"
    r"or\s+\d+=\d+|and\s+\d+=\d+|'--|-{2}|/\*|\*/|xp_)",
    re.IGNORECASE
)
XSS_PATTERNS = re.compile(
    r"(<script|</script|javascript:|onerror=|onload=|alert\(|"
    r"document\.cookie|eval\(|<img|<iframe|<svg|<body\s+on)",
    re.IGNORECASE
)
TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/etc/shadow|"
    r"win\.ini|boot\.ini|/proc/self)",
    re.IGNORECASE
)
CMDI_PATTERNS = re.compile(
    r"(;ls|;cat|;id|;whoami|\|ls|\|cat|\|id|`id`|`whoami`|"
    r"\$\(id\)|\$\(whoami\)|/bin/sh|/bin/bash|cmd\.exe)",
    re.IGNORECASE
)
SPECIAL_CHARS = re.compile(r"[<>'\"%;()&+\-=\[\]{}|\\`$]")


def extract_features(text: str, is_attack: bool) -> dict:
    """
    Transforme un payload/URL texte en features numériques.
    Les features sont calées sur top_features pour être compatibles
    avec le modèle XGBoost existant de Mylo.
    """
    if pd.isna(text) or text == '':
        text = ''
    text = str(text)
    n = len(text) if len(text) > 0 else 1

    # Compter les patterns offensifs
    sqli_hits      = len(SQLI_PATTERNS.findall(text))
    xss_hits       = len(XSS_PATTERNS.findall(text))
    traversal_hits = len(TRAVERSAL_PATTERNS.findall(text))
    cmdi_hits      = len(CMDI_PATTERNS.findall(text))
    special_hits   = len(SPECIAL_CHARS.findall(text))
    total_attacks  = sqli_hits + xss_hits + traversal_hits + cmdi_hits

    # Ratios
    special_ratio  = special_hits / n
    attack_ratio   = total_attacks / max(n / 10, 1)
    alpha_ratio    = sum(c.isalpha() for c in text) / n
    digit_ratio    = sum(c.isdigit() for c in text) / n
    upper_ratio    = sum(c.isupper() for c in text) / n

    # Encodage URL suspect
    url_encoded    = text.count('%') / n
    double_encoded = text.count('%25') / n

    # Mots suspects dans le texte
    words = re.split(r'\W+', text.lower())
    dangerous_words = {'select','union','drop','exec','script',
                       'alert','eval','passwd','shadow','bash','cmd'}
    danger_word_count = sum(1 for w in words if w in dangerous_words)

    # Mapping vers top_features
    # On utilise les features les plus discriminantes
    return {
        # Taille du payload → src_bytes
        'src_bytes':                    float(n),
        # Taille réponse estimée (0 pour requêtes web)
        'dst_bytes':                    0.0,
        # Ratio special chars → same_srv_rate (proxy densité attaque)
        'same_srv_rate':                round(special_ratio, 4),
        # Nb hits SQLi → dst_host_srv_count
        'dst_host_srv_count':           float(sqli_hits),
        # Nb hits XSS → dst_host_same_srv_rate
        'dst_host_same_srv_rate':       float(xss_hits),
        # Flag : 2=attaque SYN-like, 10=normal
        'flag':                         2.0 if is_attack else 10.0,
        # logged_in : 0 (requêtes non authentifiées généralement)
        'logged_in':                    0.0,
        # Ratio double encoding → diff_srv_rate
        'diff_srv_rate':                round(double_encoded, 4),
        # Protocol HTTP = 6 (TCP)
        'protocol_type':                6.0,
        # Nb mots → count (proxy complexité requête)
        'count':                        float(len(words)),
        # Nb hits traversal → dst_host_count
        'dst_host_count':               float(traversal_hits),
        # Ratio attaque → serror_rate
        'serror_rate':                  round(min(attack_ratio, 1.0), 4),
        # Même valeur pour dérivées
        'dst_host_serror_rate':         round(min(attack_ratio, 1.0), 4),
        'srv_serror_rate':              round(min(attack_ratio, 1.0), 4),
        # URL encoding ratio
        'dst_host_same_src_port_rate':  round(url_encoded, 4),
        # Nb hits cmdi → rerror_rate proxy
        'rerror_rate':                  float(cmdi_hits) / max(n / 10, 1),
        # Nb mots dangereux → srv_count
        'srv_count':                    float(danger_word_count),
        # Dérivées rerror
        'dst_host_rerror_rate':         float(cmdi_hits) / max(n / 10, 1),
        'dst_host_diff_srv_rate':       round(double_encoded, 4),
        # Durée 0 (pas de notion de durée dans HTTP payload)
        'duration':                     0.0,
        # Features engineerées
        'bytes_ratio':                  round(special_ratio, 4),
        'bytes_per_packet':             round(float(n) / max(len(words), 1), 4),
        'serror_diff':                  round(min(attack_ratio, 1.0) -
                                              float(cmdi_hits) / max(n/10, 1), 4),
    }


# ══════════════════════════════════════════════════════════════════════
#  1. HTTPARAMS DATASET
# ══════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  MYLO — Préparation WebAttack HTTP")
print("  Sources : HTTPParams + CSIC")
print("=" * 60)

HTTP_DIR   = r'D:\HTTPParams Dataset'
CSIC_FILE  = r'D:\csic_database.csv'
OUTPUT_DIR = r'D:\MYLO\ml\data_prepared'

all_parts = []

# ─── HTTPParams ───────────────────────────────────────────────────────
print("\n[1/4] Chargement HTTPParams...")
http_files = glob.glob(os.path.join(HTTP_DIR, '*.csv'))

if not http_files:
    print(f"  ❌ Aucun CSV dans {HTTP_DIR}")
else:
    http_dfs = []
    for f in sorted(http_files):
        try:
            df = pd.read_csv(f, encoding='utf-8', low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(f, encoding='latin-1', low_memory=False)
        http_dfs.append(df)
        print(f"  ✓ {os.path.basename(f):30s} : {len(df):>6,} lignes")

    df_http = pd.concat(http_dfs, ignore_index=True)
    # Dédupliquer sur le payload
    df_http = df_http.drop_duplicates(subset=['payload'])
    print(f"\n  Total après dédup : {len(df_http):,} lignes")
    print(f"  Distribution attack_type :")
    print(df_http['attack_type'].value_counts().to_string())

    # Mapper les labels
    http_label_map = {
        'norm':           'Normal',
        'sqli':           'WebAttack',
        'xss':            'WebAttack',
        'path-traversal': 'WebAttack',
        'cmdi':           'WebAttack',
        'sql-syntax':     'WebAttack',
        'js-syntax':      'WebAttack',
        'anom':           'WebAttack',
    }
    df_http['label_multi'] = df_http['attack_type'].map(http_label_map)
    df_http = df_http[df_http['label_multi'].notna()]

    print(f"\n  Distribution après mapping :")
    print(df_http['label_multi'].value_counts().to_string())

    # Extraire les features
    print(f"\n  Extraction des features numériques...")
    rows = []
    for _, row in df_http.iterrows():
        is_atk = row['label_multi'] == 'WebAttack'
        feats  = extract_features(row['payload'], is_atk)
        feats['label_multi'] = row['label_multi']
        rows.append(feats)

    df_http_feat = pd.DataFrame(rows)
    print(f"  ✓ {len(df_http_feat):,} lignes extraites")
    all_parts.append(df_http_feat)

# ══════════════════════════════════════════════════════════════════════
#  2. CSIC DATASET
# ══════════════════════════════════════════════════════════════════════
print("\n[2/4] Chargement CSIC...")

if not os.path.exists(CSIC_FILE):
    print(f"  ❌ Fichier introuvable : {CSIC_FILE}")
else:
    try:
        df_csic = pd.read_csv(CSIC_FILE, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df_csic = pd.read_csv(CSIC_FILE, encoding='latin-1', low_memory=False)

    print(f"  Chargé : {len(df_csic):,} lignes")
    print(f"  Distribution classification :")
    print(df_csic['classification'].value_counts().to_string())

    # classification : 0=normal, 1=anomalous
    df_csic['label_multi'] = df_csic['classification'].map({
        0: 'Normal',
        1: 'WebAttack'
    })
    df_csic = df_csic[df_csic['label_multi'].notna()]

    # Combiner URL + content comme payload
    df_csic['payload'] = (
        df_csic['URL'].fillna('') + ' ' +
        df_csic['content'].fillna('')
    ).str.strip()

    # Déduplication
    before = len(df_csic)
    df_csic = df_csic.drop_duplicates(subset=['payload'])
    print(f"  Après dédup : {len(df_csic):,} (supprimés : {before-len(df_csic):,})")
    print(f"  Distribution après mapping :")
    print(df_csic['label_multi'].value_counts().to_string())

    # Extraire les features
    print(f"\n  Extraction des features numériques...")
    rows = []
    for _, row in df_csic.iterrows():
        is_atk = row['label_multi'] == 'WebAttack'
        feats  = extract_features(row['payload'], is_atk)
        feats['label_multi'] = row['label_multi']
        rows.append(feats)

    df_csic_feat = pd.DataFrame(rows)
    print(f"  ✓ {len(df_csic_feat):,} lignes extraites")
    all_parts.append(df_csic_feat)

# ══════════════════════════════════════════════════════════════════════
#  3. FUSION + NETTOYAGE
# ══════════════════════════════════════════════════════════════════════
print("\n[3/4] Fusion + nettoyage...")

if not all_parts:
    print("❌ Aucune donnée. Vérifie les chemins."); exit(1)

df_all = pd.concat(all_parts, ignore_index=True)
df_all.replace([np.inf, -np.inf], np.nan, inplace=True)
df_all.dropna(subset=top_features, inplace=True)

# Déduplication finale sur features
before = len(df_all)
df_all = df_all.drop_duplicates(subset=top_features)
print(f"  Dédup finale : {before-len(df_all):,} supprimés")

print(f"\n  Distribution finale :")
print(df_all['label_multi'].value_counts().to_string())

# Équilibrage : prendre max 5000 Normal pour ne pas déséquilibrer
samples = []
for cls in ['Normal', 'WebAttack']:
    sub = df_all[df_all['label_multi'] == cls]
    if cls == 'Normal':
        n = min(len(sub), 5000)
    else:
        n = len(sub)  # prendre tout le WebAttack disponible
    samples.append(sub.sample(n=n, random_state=42))
    print(f"  {cls:12s} : {n:>6,} lignes conservées")

df_final = pd.concat(samples, ignore_index=True).sample(frac=1, random_state=42)

# ══════════════════════════════════════════════════════════════════════
#  4. SAUVEGARDE
# ══════════════════════════════════════════════════════════════════════
print(f"\n[4/4] Sauvegarde...")
os.makedirs(OUTPUT_DIR, exist_ok=True)
out = os.path.join(OUTPUT_DIR, 'webattack_http_prepared.csv')
df_final[top_features + ['label_multi']].to_csv(out, index=False)

print(f"\n  Total final : {len(df_final):,} lignes")
print(f"  → {out}")
print("\n" + "=" * 60)
print("  WebAttack HTTP prêt ✓")
print("  Ajoute dans train_xgb.py :")
print("    ml/data_prepared/webattack_http_prepared.csv")
print("=" * 60)