import logging
import requests
from celery import shared_task
from django.conf import settings
from .wazuh_client import WazuhClient

logger = logging.getLogger(__name__)


@shared_task(name="alerts.poll_wazuh_alerts")
def poll_wazuh_alerts():
    client = WazuhClient()
    status = client.status()
    if not status.get('success'):
        logger.error(f"[Wazuh] Statut erreur: {status.get('message')}")
        return status.get('message')

    try:
        alerts = client.get_alerts(limit=50)
    except Exception as e:
        logger.error(f"[Wazuh] Fetch erreur: {e}")
        return f"Erreur: {e}"

    if not alerts:
        return "0 alertes"

    from accounts.models import Organisation
    org = Organisation.objects.first()
    if not org:
        return "Pas d'organisation"

    processed = 0
    for alert in alerts:
        try:
            agent      = alert.get('agent', {})
            rule       = alert.get('rule', {})
            data_field = alert.get('data', {})

            src_ip = (
                data_field.get('srcip') or
                data_field.get('src_ip') or
                agent.get('ip', '0.0.0.0')
            )
            dst_ip = data_field.get('dstip') or data_field.get('dst_ip') or '172.16.1.1'

            traffic = {
                'src_ip':         src_ip,
                'dst_ip':         dst_ip,
                'protocol':       data_field.get('protocol', 'TCP'),
                'src_bytes':      float(data_field.get('size', 0)),
                'dst_bytes':      0.0,
                'duration':       0.0,
                'src_port':       int(data_field.get('srcport', 0)),
                'dst_port':       int(data_field.get('dstport', 0)),
                'wazuh_rule_id':  int(rule.get('id', 0)),
                'wazuh_severity': int(rule.get('level', 0)),
                'wazuh_agent':    agent.get('name', ''),
                'flag':           1,
                'same_srv_rate':  0.0,
                'rerror_rate':    0.0,
            }

            requests.post(
                f"{settings.MYLO_FASTAPI_URL}/predict",
                json=traffic,
                timeout=3,
            )
            processed += 1

        except Exception as e:
            logger.warning(f"[Wazuh] Alert erreur: {e}")
            continue

    return f"{processed} alertes traitées"