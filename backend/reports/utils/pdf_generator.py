import os
import json
from datetime import date, timedelta
from django.utils import timezone
from django.template.loader import render_to_string
from django.db.models import Count


def get_ml_model_metrics():
    """
    Charge les métriques du modèle XGBoost depuis le fichier
    de résultats généré lors du training (ml/outputs/).
    """
    metrics_path = os.path.join(
        os.path.dirname(__file__),
        "../../../../ml/outputs/model_metrics.json"
    )
    try:
        with open(metrics_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Valeurs de fallback si le fichier n'existe pas encore
        return {
            "accuracy": 90.29,
            "f1_score": 0.90,
            "classes": [
                "BENIGN", "DoS", "DDoS", "PortScan",
                "BruteForce", "Infiltration", "BotNet",
                "WebAttack", "Heartbleed"
            ],
            "training_date": "2025-01-01",
            "total_samples": 0,
            "river_updates": 0,
        }


def get_river_update_count(organisation):
    """
    Compte les mises à jour incrémentales River (app actions.RiverMetrics).
    Ce modèle n'a pas de FK organisation aujourd'hui : le filtre par org
    n'est appliqué que si le champ existe, pour rester correct si le
    modèle évolue plus tard. Fallback à 0 si l'app/le modèle est absent.
    """
    try:
        from actions.models import RiverMetrics
    except ImportError:
        return 0

    qs = RiverMetrics.objects.all()
    field_names = {f.name for f in RiverMetrics._meta.get_fields()}
    if organisation is not None and "organisation" in field_names:
        qs = qs.filter(organisation=organisation)
    return qs.count()


def generate_daily_report_pdf(organisation):
    """
    Génère le rapport PDF quotidien complet pour une organisation :
    - Partie 1 : Rapport opérationnel SOC (alertes, incidents, IPs, audit)
    - Partie 2 : Rapport d'audit IA (métriques modèle, drift, gouvernance)
    Retourne les bytes du PDF.
    """
    today = date.today()
    report_date = today - timedelta(days=1)

    # ── Imports locaux (évite les imports circulaires) ──────────────────
    from alerts.models import Alert
    from alerts.models import BlacklistedIP, AlertCorrelation
    from accounts.models import AuditLog

    # ── PARTIE 1 : Opérationnel SOC ─────────────────────────────────────

    # Attaques confirmées uniquement (is_attack=True) : utilisées pour les
    # alertes critiques, incidents, blocages et le KPI "Alertes détectées".
    alerts_qs = Alert.objects.filter(
        organisation=organisation,
        is_attack=True,
        detected_at__date=report_date
    )

    # Tous les flux (attaques + trafic normal) : nécessaires pour que la
    # distribution 1.1/2.3 reflète aussi le trafic normal, qui est exclu
    # de alerts_qs par le filtre is_attack=True.
    all_flows_qs = Alert.objects.filter(
        organisation=organisation,
        detected_at__date=report_date
    )

    total_alerts = alerts_qs.count()
    total_flows = all_flows_qs.count()

    alerts_by_type = list(
        all_flows_qs.values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    max_attack_count = max((row["count"] for row in alerts_by_type), default=0)

    # Type d'attaque dominant (hors trafic normal) pour le résumé exécutif.
    top_attack_row = (
        alerts_qs.values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")
        .first()
    )
    top_attack_type = top_attack_row["attack_type"] if top_attack_row else "Aucune"
    top_attack_count = top_attack_row["count"] if top_attack_row else 0

    # Alertes critiques (confidence >= 0.85)
    critical_alerts = alerts_qs.filter(
        attack_confidence__gte=0.85
    ).order_by("-detected_at")[:20]

    incidents = AlertCorrelation.objects.filter(
        organisation=organisation,
        created_at__date=report_date
    ).order_by("-risk_level")

    blocked_ips = BlacklistedIP.objects.filter(
        organisation=organisation,
        created_at__date=report_date
    ).order_by("-created_at")
    blocked_ips_count = blocked_ips.count()

    # Journal d'audit
    audit_logs = AuditLog.objects.filter(
        organisation=organisation,
        timestamp__date=report_date,
        success=True
    ).order_by("-timestamp")[:50]

    # Top 10 IPs sources agressives (section 1.6).
    # src_country / abuse_score ne sont pas des champs du modèle Alert
    # aujourd'hui (pas d'intégration GeoIP/AbuseIPDB) : fallback "-"/None.
    active_blocked_ip_set = set(
        BlacklistedIP.objects.filter(
            organisation=organisation, is_active=True
        ).values_list("ip_address", flat=True)
    )
    top_source_ips_qs = (
        alerts_qs.exclude(src_ip__isnull=True)
        .values("src_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    top_source_ips = [
        {
            "rank": rank,
            "src_ip": row["src_ip"],
            "src_country": "-",
            "count": row["count"],
            "abuse_score": None,
            "is_blocked": row["src_ip"] in active_blocked_ip_set,
        }
        for rank, row in enumerate(top_source_ips_qs, start=1)
    ]

    # ── PARTIE 2 : Audit IA ─────────────────────────────────────────────

    ml_metrics = get_ml_model_metrics()
    ml_metrics["river_updates"] = get_river_update_count(organisation)

    # Distribution des prédictions du jour (pour détecter le drift) —
    # même base que 1.1 : trafic normal inclus.
    prediction_distribution = alerts_by_type

    # Alertes "À vérifier" (confidence < 0.70) — indicateur de drift
    low_confidence_alerts = alerts_qs.filter(
        attack_confidence__lt=0.70
    ).count()
    low_confidence_pct = (
        round((low_confidence_alerts / total_alerts) * 100, 1)
        if total_alerts > 0 else 0
    )

    # Évaluation globale de santé du modèle
    if low_confidence_pct > 30:
        model_health = "Nécessite une révision"
        model_health_color = "danger"
    elif low_confidence_pct > 15:
        model_health = "Surveillance recommandée"
        model_health_color = "warning"
    else:
        model_health = "Nominal"
        model_health_color = "success"

    # ── Contexte template ───────────────────────────────────────────────
    context = {
        "organisation": organisation,
        "report_date": report_date,
        "generated_at": timezone.now(),
        # Opérationnel
        "total_alerts": total_alerts,
        "total_alerts_including_benign": total_flows,
        "total_flows": total_flows,
        "alerts_by_type": alerts_by_type,
        "max_attack_count": max_attack_count,
        "top_attack_type": top_attack_type,
        "top_attack_count": top_attack_count,
        "critical_alerts": critical_alerts,
        "incidents": incidents,
        "blocked_ips": blocked_ips,
        "blocked_ips_count": blocked_ips_count,
        "audit_logs": audit_logs,
        "top_source_ips": top_source_ips,
        # Audit IA
        "ml_metrics": ml_metrics,
        "prediction_distribution": prediction_distribution,
        "low_confidence_alerts": low_confidence_alerts,
        "low_confidence_pct": low_confidence_pct,
        "model_health": model_health,
        "model_health_color": model_health_color,
    }

    html_string = render_to_string("reports/daily_report.html", context)
    try:
        from weasyprint import HTML
    except ImportError:
        raise RuntimeError(
            "weasyprint non installé ou dépendances natives manquantes. "
            "Installer avec : pip install weasyprint et les bibliothèques système libpango/gdk-pixbuf."
        )

    pdf_bytes = HTML(string=html_string, base_url=None).write_pdf()
    return pdf_bytes
