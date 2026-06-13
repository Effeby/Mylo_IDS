import logging
from celery import shared_task
from django.core.mail import EmailMessage
from django.conf import settings
from datetime import date, timedelta

logger = logging.getLogger(__name__)


@shared_task(name="reports.send_daily_reports")
def send_daily_reports(org_id=None):
    """
    Tâche Celery déclenchée par Beat.
    Parcourt toutes les ReportConfig actives et envoie un PDF par org.
    Si org_id est fourni, n'envoie que pour cette organisation.
    """
    from .models import ReportConfig
    from .utils.pdf_generator import generate_daily_report_pdf

    configs = ReportConfig.objects.filter(
        is_active=True
    ).select_related("organisation")

    if org_id:
        configs = configs.filter(organisation_id=org_id)

    report_date = date.today() - timedelta(days=1)
    sent, failed = 0, 0

    for config in configs:
        org = config.organisation
        try:
            pdf_bytes = generate_daily_report_pdf(org)
            filename = f"mylo_rapport_{org.name.lower().replace(' ', '_')}_{report_date}.pdf"

            email = EmailMessage(
                subject=f"[Mylo IPS] Rapport de sécurité — {report_date} — {org.name}",
                body=(
                    f"Bonjour,\n\n"
                    f"Veuillez trouver en pièce jointe le rapport quotidien de sécurité "
                    f"Mylo IPS pour l'organisation {org.name}.\n\n"
                    f"Ce rapport inclut :\n"
                    f"  • Alertes et incidents corrélés du {report_date}\n"
                    f"  • IPs bloquées automatiquement\n"
                    f"  • Journal d'audit SOC\n"
                    f"  • Audit du modèle IA (XGBoost)\n\n"
                    f"— Mylo IPS"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[config.report_email],
            )
            email.attach(filename, pdf_bytes, "application/pdf")
            email.send(fail_silently=False)
            sent += 1
            logger.info(f"[Mylo] Rapport envoyé → {config.report_email} ({org.name})")

        except Exception as e:
            failed += 1
            logger.error(f"[Mylo] Échec rapport {org.name}: {e}", exc_info=True)

    return f"{sent} envoyés, {failed} échoués"