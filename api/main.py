from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import List
from contextlib import asynccontextmanager
import uvicorn
import pickle
import os

from .schemas import TrafficInput, PredictionResult, AlertItem, StatsResponse
from .predict import predict
from .models import load_models

# ─── ÉTAT GLOBAL ──────────────────────────────────────────────────────
app_state = {
    "models":       None,
    "alerts":       [],
    "stats": {
        "total_predictions": 0,
        "total_attacks":     0,
        "total_normal":      0,
        "attacks_by_type":   {"DoS": 0, "DDoS": 0, "Probe": 0, "R2L": 0, "U2R": 0,
                              "BruteForce": 0, "WebAttack": 0, "Botnet": 0, "Infiltration": 0},
    }
}

RIVER_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'models', 'mylo_river.pkl')

def load_river_model():
    """Charge le modèle River depuis le fichier pkl."""
    try:
        if os.path.exists(RIVER_MODEL_PATH):
            with open(RIVER_MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            print("  ✓ Modèle River chargé")
            return model
        else:
            print("  ℹ River — pas encore de modèle sauvegardé")
            return None
    except Exception as e:
        print(f"  ✗ Erreur chargement River: {e}")
        return None

# ─── LIFESPAN ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 45)
    print("  Mylo IPS — Démarrage API")
    print("=" * 45)
    models = load_models()
    # Ajouter River dans le dict des modèles
    models["river"] = load_river_model()
    app_state["models"] = models
    yield
    print("\n  Mylo IPS — Arrêt API")

# ─── APP ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Mylo IPS API",
    description="AI-powered Intrusion Prevention System",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── ENDPOINTS ────────────────────────────────────────────────────────

@app.get("/health")
def health():
    models_loaded = app_state["models"] is not None
    river_loaded  = app_state["models"].get("river") is not None if models_loaded else False
    return {
        "status":        "ok" if models_loaded else "error",
        "models_loaded": models_loaded,
        "river_loaded":  river_loaded,
        "version":       "1.0.0",
        "timestamp":     datetime.now().isoformat(),
    }


@app.post("/predict", response_model=PredictionResult)
def predict_endpoint(data: TrafficInput):
    if app_state["models"] is None:
        raise HTTPException(status_code=503, detail="Modèles non chargés")

    result = predict(data, app_state["models"])

    # Stats
    app_state["stats"]["total_predictions"] += 1
    if result.is_attack:
        app_state["stats"]["total_attacks"] += 1
        attack = result.attack_type
        if attack in app_state["stats"]["attacks_by_type"]:
            app_state["stats"]["attacks_by_type"][attack] += 1
        app_state["alerts"].append({
            "id":                len(app_state["alerts"]) + 1,
            "timestamp":         result.timestamp,
            "attack_type":       result.attack_type,
            "severity":          result.severity,
            "binary_confidence": result.binary_confidence,
            "attack_confidence": result.attack_confidence,
            "src_bytes":         data.src_bytes,
            "dst_bytes":         data.dst_bytes,
            "duration":          data.duration,
            "river_used":        result.river_used,
        })
        if len(app_state["alerts"]) > 100:
            app_state["alerts"].pop(0)
    else:
        app_state["stats"]["total_normal"] += 1

    return result


@app.post("/reload-river")
def reload_river():
    """Recharge le modèle River depuis le fichier pkl — appeler après apprentissage."""
    try:
        app_state["models"]["river"] = load_river_model()
        return {"status": "ok", "river_loaded": app_state["models"]["river"] is not None}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.get("/alerts", response_model=List[AlertItem])
def get_alerts(limit: int = 20):
    limit = min(limit, 100)
    alerts = app_state["alerts"][-limit:]
    return list(reversed(alerts))


@app.get("/stats", response_model=StatsResponse)
def get_stats():
    s      = app_state["stats"]
    total  = s["total_predictions"]
    models = app_state["models"]
    return StatsResponse(
        total_predictions = total,
        total_attacks     = s["total_attacks"],
        total_normal      = s["total_normal"],
        attack_rate       = round(s["total_attacks"] / total, 4) if total > 0 else 0.0,
        attacks_by_type   = s["attacks_by_type"],
        model_info        = {
            "classifier":        "XGBoost + River",
            "features":          len(models["xgb_features"]) if models else 0,
            "classes":           list(models["label_encoder"].classes_) if models else [],
            "datasets":          ["NSL-KDD", "CICIDS2017", "NIDS", "CIC-IDS2018", "UNSW-NB15"],
            "river_loaded":      models.get("river") is not None,
            "binary_threshold":  0.50,
        }
    )


@app.delete("/alerts")
def clear_alerts():
    app_state["alerts"].clear()
    return {"message": "Alertes effacées", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
