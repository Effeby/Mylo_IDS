from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ─── INPUT ────────────────────────────────────────────────────────────
class TrafficInput(BaseModel):
    # Features NSL-KDD principales
    src_bytes:                      float = 0
    dst_bytes:                      float = 0
    same_srv_rate:                  float = 0
    dst_host_srv_count:             float = 0
    dst_host_same_srv_rate:         float = 0
    flag:                           int   = 0
    logged_in:                      int   = 0
    diff_srv_rate:                  float = 0
    protocol_type:                  int   = 0
    count:                          float = 0
    dst_host_count:                 float = 0
    serror_rate:                    float = 0
    dst_host_serror_rate:           float = 0
    srv_serror_rate:                float = 0
    dst_host_same_src_port_rate:    float = 0
    rerror_rate:                    float = 0
    srv_count:                      float = 0
    dst_host_rerror_rate:           float = 0
    dst_host_diff_srv_rate:         float = 0
    duration:                       float = 0

    # IPs (optionnel — utilisé pour whitelist et sauvegarde)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "src_bytes": 491,
                "dst_bytes": 0,
                "duration": 0,
                "protocol_type": 2,
                "flag": 10,
                "logged_in": 0,
                "count": 2,
                "srv_count": 2,
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 150,
                "dst_host_srv_count": 25,
                "dst_host_same_srv_rate": 0.17,
                "dst_host_diff_srv_rate": 0.03,
                "dst_host_same_src_port_rate": 0.17,
                "dst_host_serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "dst_host_rerror_rate": 0.05,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1"
            }
        }

# ─── OUTPUT ───────────────────────────────────────────────────────────
# Ajouter ces deux champs optionnels à la classe PredictionResult dans api/schemas.py

class PredictionResult(BaseModel):
    is_attack:         bool
    binary_label:      str
    binary_confidence: float
    attack_type:       str
    attack_confidence: float
    severity:          str
    alert_status:      str
    timestamp:         datetime
    river_used:        Optional[bool]  = False
    river_class:       Optional[str]   = None
    
    anomaly_score: float = 0.0
    if_triggered:  bool  = False
    abuse_score:   int | None = None
    abuse_country: str | None = None
    is_tor:        bool | None = None


# ─── ITEMS LISTE ──────────────────────────────────────────────────────
class AlertItem(BaseModel):
    id:                 int
    timestamp:          datetime
    attack_type:        str
    severity:           str
    binary_confidence:  float
    attack_confidence:  float
    src_bytes:          float
    dst_bytes:          float
    duration:           float
    src_ip:             Optional[str] = None
    dst_ip:             Optional[str] = None
    alert_status:       str = "Nouvelle"


# ─── STATS ────────────────────────────────────────────────────────────
class StatsResponse(BaseModel):
    total_predictions:  int
    total_attacks:      int
    total_normal:       int
    attack_rate:        float
    attacks_by_type:    dict    # 9 classes
    model_info:         dict

    # Nouveaux champs stats
    false_positives:    int = 0
    under_review:       int = 0     # alertes "À vérifier"
    ignored:            int = 0     # alertes "Ignorées" (whitelist)