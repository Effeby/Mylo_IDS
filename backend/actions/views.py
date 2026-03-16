from django.shortcuts import render
import pickle
from pathlib import Path
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from river import tree, preprocessing, metrics
from .models import RiverMetrics

# ─── CHEMINS ──────────────────────────────────────────────────────────
BASE_DIR         = Path(__file__).resolve().parent.parent.parent
MODELS_DIR       = BASE_DIR / 'ml' / 'models'
RIVER_PATH       = MODELS_DIR / 'mylo_river.pkl'
RIVER_STATE_PATH = MODELS_DIR / 'mylo_river_state.pkl'

XGB_FEATURES = [
    "src_bytes", "dst_bytes", "same_srv_rate", "dst_host_srv_count",
    "dst_host_same_srv_rate", "flag", "logged_in", "diff_srv_rate",
    "protocol_type", "count", "dst_host_count", "serror_rate",
    "dst_host_serror_rate", "srv_serror_rate", "dst_host_same_src_port_rate",
    "rerror_rate", "srv_count", "dst_host_rerror_rate",
    "dst_host_diff_srv_rate", "duration",
    "bytes_ratio", "bytes_per_packet", "serror_diff",
]

ALL_CLASSES = ['Normal', 'DoS', 'DDoS', 'Probe', 'R2L', 'U2R',
               'BruteForce', 'WebAttack', 'Botnet', 'Infiltration']

# ─── ÉTAT GLOBAL RIVER ────────────────────────────────────────────────
_river_state = {
    'model':    None,
    'metric':   metrics.Accuracy(),
    'report':   metrics.ClassificationReport(),   # ← F1 par classe
    'counts':   {cls: 0 for cls in ALL_CLASSES},
    'total':    0,
    'history':  [],   # historique léger en mémoire
    'loaded':   False,
}


def _load_river_model():
    if RIVER_PATH.exists():
        with open(RIVER_PATH, 'rb') as f:
            print("  ✓ River model chargé depuis", RIVER_PATH)
            return pickle.load(f)
    print("  ℹ  Nouveau modèle River créé")
    return (
        preprocessing.StandardScaler() |
        tree.HoeffdingAdaptiveTreeClassifier(
            grace_period=50, delta=1e-5, tau=0.05,
        )
    )


def _load_river_state():
    if RIVER_STATE_PATH.exists():
        try:
            with open(RIVER_STATE_PATH, 'rb') as f:
                state = pickle.load(f)
                _river_state['total']   = state.get('total', 0)
                _river_state['counts']  = state.get('counts', {cls: 0 for cls in ALL_CLASSES})
                _river_state['history'] = state.get('history', [])
            # S'assurer que report existe toujours (peut manquer si state ancien)
            if 'report' not in _river_state:
                _river_state['report'] = metrics.ClassificationReport()
            print(f"  ✓ River state chargé : {_river_state['total']} flux appris")
        except Exception as e:
            print(f"  ⚠  Erreur chargement River state : {e}")


def _save_river():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RIVER_PATH, 'wb') as f:
        pickle.dump(_river_state['model'], f)
    with open(RIVER_STATE_PATH, 'wb') as f:
        pickle.dump({
            'total':   _river_state['total'],
            'counts':  _river_state['counts'],
            'history': _river_state['history'][-200:],  # garder les 200 derniers
        }, f)


def _get_model():
    if not _river_state['loaded']:
        _river_state['model']  = _load_river_model()
        _load_river_state()
        _river_state['loaded'] = True
    return _river_state['model']


def _get_f1_scores():
    """Extrait les F1 scores par classe depuis ClassificationReport."""
    f1_scores = {}
    try:
        report = _river_state['report']
        for cls in ALL_CLASSES:
            try:
                f1 = report[cls].f1_score.get()
                f1_scores[cls] = round(f1, 4)
            except Exception:
                f1_scores[cls] = 0.0
    except Exception:
        f1_scores = {cls: 0.0 for cls in ALL_CLASSES}
    return f1_scores


class RiverLearnView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        features   = request.data.get('features', {})
        true_label = request.data.get('true_label') or request.data.get('label')

        if not features or not true_label:
            return Response({'error': 'features et label requis'}, status=400)
        if true_label not in ALL_CLASSES:
            return Response({'error': f'Label invalide. Classes : {ALL_CLASSES}'}, status=400)

        model = _get_model()
        x = {k: float(features.get(k, 0)) for k in XGB_FEATURES}

        # Prédire AVANT d'apprendre (évaluation honnête)
        y_pred = model.predict_one(x)

        # Mettre à jour les métriques
        if y_pred is not None:
            _river_state['metric'].update(true_label, y_pred)
            _river_state['report'].update(true_label, y_pred)

        # Apprendre
        model.learn_one(x, true_label)
        _river_state['total']  += 1
        _river_state['counts'][true_label] = \
            _river_state['counts'].get(true_label, 0) + 1

        accuracy = round(_river_state['metric'].get(), 4)

        # ── Historique en mémoire (pour le graphique) ─────────────────
        from django.utils import timezone
        _river_state['history'].append({
            'total':    _river_state['total'],
            'accuracy': accuracy,
            'label':    true_label,
            'correct':  y_pred == true_label,
            'time':     timezone.now().isoformat(),
        })

        # ── Sauvegarder à chaque apprentissage ────────────────────────
        _save_river()

        # ── Persister en BDD tous les 5 exemples (était 50) ───────────
        if _river_state['total'] % 5 == 0:
            try:
                RiverMetrics.objects.create(
                    accuracy      = accuracy,
                    total_learned = _river_state['total'],
                    dos_learned   = _river_state['counts'].get('DoS', 0),
                    ddos_learned  = _river_state['counts'].get('DDoS', 0),
                    probe_learned = _river_state['counts'].get('Probe', 0),
                    r2l_learned   = _river_state['counts'].get('R2L', 0),
                    u2r_learned   = _river_state['counts'].get('U2R', 0),
                    brute_learned = _river_state['counts'].get('BruteForce', 0),
                    web_learned   = _river_state['counts'].get('WebAttack', 0),
                    bot_learned   = _river_state['counts'].get('Botnet', 0),
                    infil_learned = _river_state['counts'].get('Infiltration', 0),
                )
            except Exception:
                pass

        print(f"  🧠 River [{true_label:12s}] "
              f"{'✓' if y_pred == true_label else '✗'} "
              f"acc:{accuracy:.3f} total:{_river_state['total']}")

        return Response({
            'learned':   true_label,
            'predicted': y_pred,
            'correct':   y_pred == true_label,
            'total':     _river_state['total'],
            'accuracy':  accuracy,
            'counts':    _river_state['counts'],
        })


class RiverPredictView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        features = request.data.get('features', {})
        model    = _get_model()
        x        = {k: float(features.get(k, 0)) for k in XGB_FEATURES}
        prediction = model.predict_one(x)
        try:
            proba = model.predict_proba_one(x)
        except Exception:
            proba = {}
        return Response({'prediction': prediction, 'probabilities': proba})


class RiverStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _get_model()

        # Historique BDD
        db_history = list(
            RiverMetrics.objects.values(
                'accuracy', 'total_learned', 'recorded_at'
            ).order_by('recorded_at')[:100]
        )
        for h in db_history:
            h['recorded_at'] = h['recorded_at'].isoformat()

        # Fusionner historique mémoire + BDD
        mem_history = _river_state['history'][-50:]

        # F1 par classe
        f1_scores = _get_f1_scores()

        # Drift detection — comparer accuracy récente vs globale
        drift_detected = False
        drift_info     = None
        if len(mem_history) >= 20:
            recent_10   = mem_history[-10:]
            previous_10 = mem_history[-20:-10]
            recent_acc   = sum(1 for h in recent_10   if h['correct']) / 10
            previous_acc = sum(1 for h in previous_10 if h['correct']) / 10
            drop = previous_acc - recent_acc
            if drop > 0.20:  # Chute > 20% → drift
                drift_detected = True
                drift_info     = {
                    'previous_accuracy': round(previous_acc, 3),
                    'recent_accuracy':   round(recent_acc, 3),
                    'drop':              round(drop, 3),
                }

        return Response({
            'model_type':      'HoeffdingAdaptiveTreeClassifier',
            'classes':         ALL_CLASSES,
            'total_learned':   _river_state['total'],
            'accuracy':        round(_river_state['metric'].get(), 4),
            'counts':          _river_state['counts'],
            'f1_scores':       f1_scores,
            'model_saved':     RIVER_PATH.exists(),
            'state_saved':     RIVER_STATE_PATH.exists(),
            'history':         db_history,
            'recent_history':  mem_history,
            'drift_detected':  drift_detected,
            'drift_info':      drift_info,
            'status':          'active' if _river_state['total'] > 0 else 'waiting',
        })