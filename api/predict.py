import numpy as np
import pandas as pd
import httpx
import os
from datetime import datetime
from .schemas import TrafficInput, PredictionResult

# ─── THRESHOLDS AFFINÉS ───────────────────────────────────────────────────────
CLASS_THRESHOLDS = {
    "Normal":      0.40,
    "DoS":         0.65,
    "DDoS":        0.60,
    "Probe":       0.55,
    "BruteForce":  0.35,
    "WebAttack":   0.35,
    "Botnet":      0.25,
    "Infiltration":0.20,
    "R2L":         0.25,
    "U2R":         0.15,
}

BINARY_THRESHOLD = 0.50

SEVERITY_MAP = {
    "Normal":      "LOW",
    "DoS":         "HIGH",
    "DDoS":        "HIGH",
    "Probe":       "MEDIUM",
    "BruteForce":  "HIGH",
    "WebAttack":   "CRITICAL",
    "Botnet":      "CRITICAL",
    "Infiltration":"CRITICAL",
    "R2L":         "CRITICAL",
    "U2R":         "CRITICAL",
    "Anomalie":    "HIGH",       # Zero-day détecté par Isolation Forest
}

IP_WHITELIST_PREFIXES = [
    "13.107.", "52.96.", "52.112.", "52.113.", "52.114.", "52.115.",
    "104.44.", "40.96.", "40.104.", "20.190.", "20.42.",
    "34.96.", "34.64.", "142.250.", "172.217.", "216.58.", "74.125.",
    "35.190.", "34.160.",
    "1.1.1.", "1.0.0.", "104.16.", "104.17.", "104.18.", "104.19.",
    "41.74.", "41.75.", "197.255.", "41.202.",
    "52.84.", "52.85.", "143.204.", "99.86.",
    "192.168.", "10.", "172.16.", "172.17.", "172.18.",
    "127.", "224.0.",
]

CONFIDENCE_ALERT_THRESHOLD = 0.70

# Seuil River — confiance minimale pour que River override XGBoost
RIVER_OVERRIDE_THRESHOLD = 0.75

# ─── Isolation Forest — seuil score anomalie ─────────────────────────
# score_samples retourne des valeurs négatives : plus c'est bas, plus c'est anormal
# -0.5 est un seuil raisonnable (les normaux sont autour de -0.36 en moyenne)
IF_SCORE_THRESHOLD = -0.50

# ─── AbuseIPDB ────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL       = "https://api.abuseipdb.com/api/v2/check"
# Score de confiance AbuseIPDB au-delà duquel on force is_attack=True
ABUSEIPDB_THRESHOLD = 50


def is_whitelisted(ip: str) -> bool:
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in IP_WHITELIST_PREFIXES)


def get_alert_status(is_attack: bool, confidence: float, src_ip: str) -> str:
    if not is_attack:
        return "Normal"
    if is_whitelisted(src_ip):
        return "Ignorée"
    if confidence < CONFIDENCE_ALERT_THRESHOLD:
        return "À vérifier"
    return "Nouvelle"


def prepare_input(data: TrafficInput, features: list) -> pd.DataFrame:
    row = {
        "src_bytes":                    data.src_bytes,
        "dst_bytes":                    data.dst_bytes,
        "same_srv_rate":                data.same_srv_rate,
        "dst_host_srv_count":           data.dst_host_srv_count,
        "dst_host_same_srv_rate":       data.dst_host_same_srv_rate,
        "flag":                         data.flag,
        "logged_in":                    data.logged_in,
        "diff_srv_rate":                data.diff_srv_rate,
        "protocol_type":                data.protocol_type,
        "count":                        data.count,
        "dst_host_count":               data.dst_host_count,
        "serror_rate":                  data.serror_rate,
        "dst_host_serror_rate":         data.dst_host_serror_rate,
        "srv_serror_rate":              data.srv_serror_rate,
        "dst_host_same_src_port_rate":  data.dst_host_same_src_port_rate,
        "rerror_rate":                  data.rerror_rate,
        "srv_count":                    data.srv_count,
        "dst_host_rerror_rate":         data.dst_host_rerror_rate,
        "dst_host_diff_srv_rate":       data.dst_host_diff_srv_rate,
        "duration":                     data.duration,
        "bytes_ratio":      data.src_bytes / (data.dst_bytes + 1),
        "bytes_per_packet": data.src_bytes / (data.count + 1),
        "serror_diff":      data.serror_rate - data.rerror_rate,
    }
    return pd.DataFrame([row])[features]


def get_river_prediction(features_dict: dict, models: dict) -> dict | None:
    """
    Interroge River (HoeffdingAdaptiveTree) pour une deuxième opinion.
    Retourne None si River n'a pas assez appris (< 10 exemples).
    """
    try:
        river_model = models.get("river")
        if river_model is None:
            return None

        total_learned = getattr(river_model, '_n_samples_seen', 0)
        if total_learned < 10:
            return None

        proba = river_model.predict_proba_one(features_dict)
        if not proba:
            return None

        best_class = max(proba, key=proba.get)
        best_conf  = proba[best_class]

        return {
            'class':      best_class,
            'confidence': best_conf,
            'proba':      proba,
        }
    except Exception:
        return None


def get_isolation_forest_result(X: pd.DataFrame, models: dict) -> dict:
    """
    Interroge l'Isolation Forest pour détecter une anomalie potentielle zero-day.
    Retourne un dict avec is_anomaly (bool) et anomaly_score (float).
    """
    iso = models.get("isolation_forest")
    if iso is None:
        return {"is_anomaly": False, "anomaly_score": 0.0, "if_available": False}

    try:
        score = float(iso.score_samples(X)[0])
        is_anomaly = score < IF_SCORE_THRESHOLD
        return {
            "is_anomaly":    is_anomaly,
            "anomaly_score": round(score, 4),
            "if_available":  True,
        }
    except Exception:
        return {"is_anomaly": False, "anomaly_score": 0.0, "if_available": False}


def check_abuseipdb(ip: str) -> dict:
    """
    Interroge AbuseIPDB pour obtenir le score de réputation d'une IP.
    Retourne un dict vide si la clé API n'est pas configurée ou si erreur.
    """
    if not ABUSEIPDB_API_KEY or not ip or is_whitelisted(ip):
        return {}

    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_score":      data.get("abuseConfidenceScore", 0),
                    "total_reports":    data.get("totalReports", 0),
                    "country_code":     data.get("countryCode", ""),
                    "is_tor":           data.get("isTor", False),
                    "last_reported_at": data.get("lastReportedAt", ""),
                }
    except Exception:
        pass
    return {}


def predict(data: TrafficInput, models: dict) -> PredictionResult:
    """
    Pipeline d'inférence complet :
    1. Whitelist check
    2. XGBoost binaire + multi-classes
    3. Isolation Forest (détection zero-day)
    4. River deuxième opinion (si disponible)
    5. AbuseIPDB enrichissement réputation IP
    6. Fusion → décision finale
    """
    xgb_binary    = models["xgb_binary"]
    xgb_multi     = models["xgb_multi"]
    features      = models["xgb_features"]
    label_encoder = models["label_encoder"]

    src_ip = getattr(data, 'src_ip', '') or ''
    dst_ip = getattr(data, 'dst_ip', '') or ''

    # ── 1. Whitelist check ────────────────────────────────────────────
    if is_whitelisted(src_ip) and is_whitelisted(dst_ip):
        return PredictionResult(
            is_attack         = False,
            binary_label      = "Normal",
            binary_confidence = 0.0,
            attack_type       = "Normal",
            attack_confidence = 1.0,
            severity          = "LOW",
            alert_status      = "Ignorée",
            timestamp         = datetime.now(),
            anomaly_score     = 0.0,
            if_triggered      = False,
        )

    # ── 2. XGBoost ───────────────────────────────────────────────────
    X = prepare_input(data, features)

    binary_proba = xgb_binary.predict_proba(X)[0][1]
    is_attack    = bool(binary_proba >= BINARY_THRESHOLD)
    binary_label = "Attaque" if is_attack else "Normal"

    multi_proba = xgb_multi.predict_proba(X)[0]
    classes     = label_encoder.classes_

    adjusted = [
        p / CLASS_THRESHOLDS.get(cls, 0.40)
        for cls, p in zip(classes, multi_proba)
    ]
    predicted_idx = int(np.argmax(adjusted))
    attack_type   = classes[predicted_idx]
    attack_conf   = float(multi_proba[predicted_idx])

    if is_attack and is_whitelisted(src_ip):
        is_attack    = False
        attack_type  = "Normal"
        binary_label = "Normal"

    # ── 3. Isolation Forest (zero-day) ───────────────────────────────
    if_result  = get_isolation_forest_result(X, models)
    if_triggered = False

    if if_result["if_available"] and if_result["is_anomaly"]:
        # XGBoost dit Normal mais IF détecte une anomalie → potentiel zero-day
        if not is_attack:
            is_attack    = True
            attack_type  = "Anomalie"
            binary_label = "Attaque"
            # Confiance estimée depuis le score IF (normalisée entre 0.5 et 0.9)
            normalized   = min(0.9, 0.5 + abs(if_result["anomaly_score"] + IF_SCORE_THRESHOLD) * 0.8)
            attack_conf  = round(normalized, 4)
            binary_proba = attack_conf
            if_triggered = True

    # ── 4. River deuxième opinion ─────────────────────────────────────
    river_used  = False
    river_class = None

    features_dict = {
        'src_bytes': data.src_bytes, 'dst_bytes': data.dst_bytes,
        'same_srv_rate': data.same_srv_rate, 'dst_host_srv_count': data.dst_host_srv_count,
        'dst_host_same_srv_rate': data.dst_host_same_srv_rate, 'flag': data.flag,
        'logged_in': data.logged_in, 'diff_srv_rate': data.diff_srv_rate,
        'protocol_type': data.protocol_type, 'count': data.count,
        'dst_host_count': data.dst_host_count, 'serror_rate': data.serror_rate,
        'dst_host_serror_rate': data.dst_host_serror_rate, 'srv_serror_rate': data.srv_serror_rate,
        'dst_host_same_src_port_rate': data.dst_host_same_src_port_rate,
        'rerror_rate': data.rerror_rate, 'srv_count': data.srv_count,
        'dst_host_rerror_rate': data.dst_host_rerror_rate,
        'dst_host_diff_srv_rate': data.dst_host_diff_srv_rate,
        'duration': data.duration,
        'bytes_ratio': data.src_bytes / (data.dst_bytes + 1),
        'bytes_per_packet': data.src_bytes / (data.count + 1),
        'serror_diff': data.serror_rate - data.rerror_rate,
    }

    river_pred = get_river_prediction(features_dict, models)

    if river_pred and river_pred['confidence'] >= RIVER_OVERRIDE_THRESHOLD:
        river_class = river_pred['class']
        if not is_attack and river_class != 'Normal':
            is_attack    = True
            attack_type  = river_class
            attack_conf  = river_pred['confidence']
            binary_label = "Attaque"
            binary_proba = max(binary_proba, river_pred['confidence'])
            river_used   = True
        elif is_attack and river_class != 'Normal' and river_class != attack_type:
            if river_pred['confidence'] > attack_conf:
                attack_type = river_class
                attack_conf = river_pred['confidence']
                river_used  = True

    # ── 5. AbuseIPDB enrichissement ──────────────────────────────────
    abuse_info = check_abuseipdb(src_ip)
    if abuse_info and abuse_info.get("abuse_score", 0) >= ABUSEIPDB_THRESHOLD:
        # IP connue malveillante → forcer l'alerte même si tout le reste dit Normal
        if not is_attack:
            is_attack    = True
            attack_type  = attack_type if attack_type != "Normal" else "Probe"
            binary_label = "Attaque"
            binary_proba = max(binary_proba, abuse_info["abuse_score"] / 100)
            attack_conf  = binary_proba

    # ── 6. Sévérité et statut ─────────────────────────────────────────
    severity     = SEVERITY_MAP.get(attack_type, "MEDIUM")
    alert_status = get_alert_status(is_attack, binary_proba, src_ip)

    return PredictionResult(
        is_attack         = is_attack,
        binary_label      = binary_label,
        binary_confidence = round(float(binary_proba), 4),
        attack_type       = attack_type,
        attack_confidence = round(attack_conf, 4),
        severity          = severity,
        alert_status      = alert_status,
        timestamp         = datetime.now(),
        river_used        = river_used,
        river_class       = river_class,
        # ── Nouveaux champs ──────────────────────────────────────────
        anomaly_score     = if_result.get("anomaly_score", 0.0),
        if_triggered      = if_triggered,
        abuse_score       = abuse_info.get("abuse_score", None),
        abuse_country     = abuse_info.get("country_code", None),
        is_tor            = abuse_info.get("is_tor", None),
    )