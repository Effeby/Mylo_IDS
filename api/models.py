import joblib
import os

# ─── CHEMINS ──────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR  = os.path.join(BASE_DIR, "ml", "models")

# ─── CHARGEMENT ───────────────────────────────────────────────────────
def load_models():
    """Charge tous les modèles et encoders au démarrage de l'API."""
    print("  Chargement des modèles Mylo IDS...")

    models = {}

    try:
        models["xgb_binary"]    = joblib.load(os.path.join(MODELS_DIR, "mylo_xgb_binary.pkl"))
        print("  ✓ mylo_xgb_binary.pkl")

        models["xgb_multi"]     = joblib.load(os.path.join(MODELS_DIR, "mylo_xgb_multiclass.pkl"))
        print("  ✓ mylo_xgb_multiclass.pkl")

        models["xgb_features"]  = joblib.load(os.path.join(MODELS_DIR, "xgb_features.pkl"))
        print("  ✓ xgb_features.pkl")

        models["label_encoder"] = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        print("  ✓ label_encoder.pkl")

        models["encoders"]      = joblib.load(os.path.join(MODELS_DIR, "encoders.pkl"))
        print("  ✓ encoders.pkl")

        print("  Tous les modèles chargés ✓\n")

    except FileNotFoundError as e:
        print(f"  ERREUR : fichier manquant → {e}")
        raise

    return models