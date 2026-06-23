import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")


def load_models():
    print("  Chargement des modèles Mylo IPS...")
    
    models = {}

    # ─── River ─────────────────────────────
    river_path = os.path.join(MODELS_DIR, "mylo_river.pkl")
    if os.path.exists(river_path):
        models["river"] = joblib.load(river_path)
        print("  ✓ mylo_river.pkl")
    else:
        models["river"] = None
        print("  ⚠️ mylo_river.pkl absent")

    # ─── XGBoost ───────────────────────────
    try:
        models["xgb_binary"] = joblib.load(os.path.join(MODELS_DIR, "mylo_xgb_binary.pkl"))
        models["xgb_binary"].set_params(nthread=2)
        print("  ✓ mylo_xgb_binary.pkl")

        models["xgb_multi"] = joblib.load(os.path.join(MODELS_DIR, "mylo_xgb_multiclass.pkl"))
        models["xgb_multi"].set_params(nthread=2)
        print("  ✓ mylo_xgb_multiclass.pkl")

        models["xgb_features"] = joblib.load(os.path.join(MODELS_DIR, "xgb_features.pkl"))
        print("  ✓ xgb_features.pkl")

        models["label_encoder"] = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        print("  ✓ label_encoder.pkl")

        models["encoders"] = joblib.load(os.path.join(MODELS_DIR, "encoders.pkl"))
        print("  ✓ encoders.pkl")

    except FileNotFoundError as e:
        print(f"  ERREUR : fichier manquant → {e}")
        raise

    # ─── Isolation Forest (optionnel — non bloquant) ──────────────────
    iso_path = os.path.join(MODELS_DIR, "mylo_isolation_forest.pkl")
    if os.path.exists(iso_path):
        models["isolation_forest"] = joblib.load(iso_path)
        print("  ✓ mylo_isolation_forest.pkl")
    else:
        models["isolation_forest"] = None
        print("  ⚠️  mylo_isolation_forest.pkl absent — détection zero-day désactivée")

    print("  Tous les modèles chargés ✓\n")
    return models
    


