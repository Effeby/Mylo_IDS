import logging
import requests
from celery import shared_task
from django.conf import settings
from .wazuh_client import WazuhClient
from .wazuh_rules import get_alert_class, is_rule_id_mapped, CLASS_DEFAULTS, NORMAL, SUSPICIOUS

logger = logging.getLogger(__name__)


def _has_sufficient_features(traffic: dict) -> bool:
    """
    Heuristique de suffisance des features pour la classification ML.

    Les alertes Wazuh ne portent pas toujours de données de flux réseau
    (octets, ports) — dans ce cas le modèle XGBoost n'a quasiment aucun
    signal discriminant et sa prédiction n'est pas fiable. On considère
    les features suffisantes dès qu'au moins une métrique de flux réelle
    (non nulle) est disponible.
    """
    return any([
        traffic.get('src_bytes', 0) > 0,
        traffic.get('dst_bytes', 0) > 0,
        traffic.get('src_port', 0) > 0,
        traffic.get('dst_port', 0) > 0,
    ])


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

            # IP whitelistée (src ou dst) → on ignore silencieusement, pas de save BD.
            from .models import WhitelistedIP
            if WhitelistedIP.objects.filter(organisation=org, ip_address__in=[src_ip, dst_ip]).exists():
                continue

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

            # Call FastAPI ML predict endpoint
            try:
                resp = requests.post(
                    f"{settings.MYLO_FASTAPI_URL}/predict",
                    json=traffic,
                    timeout=30,
                )
                if not resp.ok:
                    logger.warning(f"[Wazuh] FastAPI predict failed: {resp.status_code}")
                    continue
                prediction = resp.json()

                # Classification par rule_id Wazuh (mapping centralisé)
                rule_id    = int(rule.get('id', 0))
                rule_level = int(rule.get('level', 0))

                if is_rule_id_mapped(rule_id):
                    mylo_class = get_alert_class(rule_id)
                    defaults   = CLASS_DEFAULTS[mylo_class]
                    prediction['attack_type']       = mylo_class
                    prediction['is_attack']          = mylo_class != NORMAL
                    prediction['attack_confidence']  = defaults['confidence']
                    prediction['binary_confidence']  = defaults['confidence']
                    prediction['binary_label']       = 'Attack' if mylo_class != NORMAL else 'Normal'
                    prediction['severity']           = defaults['severity']
                    prediction['alert_status']       = 'Nouvelle' if mylo_class != NORMAL else 'Normal'
                else:
                    # rule_id non mappé — journalisé pour enrichir le mapping progressivement
                    logger.info(
                        f"[Wazuh] rule_id non mappé: {rule_id} (niveau {rule_level}) "
                        f"— {rule.get('description', '')}"
                    )
                    try:
                        from accounts.models import AuditLog
                        AuditLog.log(
                            action='wazuh_rule_unmapped',
                            organisation=org,
                            description=(
                                f"Rule ID Wazuh non mappé : {rule_id} (niveau {rule_level}) "
                                f"— {rule.get('description', '')}"
                            ),
                            object_type='WazuhRule',
                            object_id=rule_id,
                            success=False,
                            extra_data={
                                'rule_id':          rule_id,
                                'rule_level':        rule_level,
                                'rule_description':  rule.get('description', ''),
                                'rule_groups':       rule.get('groups', []),
                                'src_ip':            src_ip,
                            },
                        )
                    except Exception as audit_err:
                        logger.warning(f"[Wazuh] AuditLog rule non mappé erreur: {audit_err}")

                    # Pas de règle connue : on tente la classification ML (XGBoost,
                    # déjà calculée ci-dessus via /predict). Si les features dispo
                    # sont insuffisantes pour faire confiance à cette prédiction,
                    # on bascule sur 'Suspicious' plutôt que de classer en Normal.
                    if not _has_sufficient_features(traffic):
                        defaults = CLASS_DEFAULTS[SUSPICIOUS]
                        prediction['attack_type']       = SUSPICIOUS
                        prediction['is_attack']          = True
                        prediction['attack_confidence']  = defaults['confidence']
                        prediction['binary_confidence']  = defaults['confidence']
                        prediction['binary_label']       = 'Suspicious'
                        prediction['severity']           = defaults['severity']
                        prediction['alert_status']       = 'À vérifier'
                    # sinon : on garde la prédiction XGBoost/River déjà renvoyée par /predict

                # Persist in Django DB so Wazuh alerts are visible in the UI
                from .models import Alert
                from .views import (
                    compute_detection_score, compute_cvss_severity,
                    get_asset_for_ip
                )

                asset = get_asset_for_ip(org, dst_ip) or get_asset_for_ip(org, src_ip)
                detection_score = compute_detection_score(prediction)
                criticality = asset.criticality if asset else 2
                asset_multiplier = asset.multiplier if asset else 1.0
                alert_status = prediction.get('alert_status', 'Nouvelle')
                severity, final_score, asset_multiplier = compute_cvss_severity(
                    detection_score,
                    criticality=criticality,
                    attack_type=prediction.get('attack_type', 'Normal'),
                    asset_multiplier=asset_multiplier,
                )

                STATUS_MAP = {
                    'Nouvelle':   'new',
                    'À vérifier': 'under_review',
                    'Ignorée':    'ignored',
                    'Normal':     'normal',
                }
                db_status = STATUS_MAP.get(alert_status, 'new')

                Alert.objects.create(
                    organisation      = org,
                    attack_type       = prediction.get('attack_type', 'Normal'),
                    severity          = severity,
                    binary_confidence = prediction.get('binary_confidence', 0),
                    attack_confidence = prediction.get('attack_confidence', 0),
                    detection_score   = detection_score,
                    final_score       = final_score,
                    asset_multiplier  = asset_multiplier,
                    asset_name        = asset.name if asset else '',
                    asset_criticality = criticality,
                    is_attack         = prediction.get('is_attack', False),
                    src_ip            = src_ip,
                    dst_ip            = dst_ip,
                    protocol          = traffic.get('protocol', 'TCP'),
                    src_bytes         = traffic.get('src_bytes', 0),
                    dst_bytes         = traffic.get('dst_bytes', 0),
                    duration          = traffic.get('duration', 0),
                    status            = db_status,
                    features          = {
                        **{k: v for k, v in traffic.items() if k not in ('src_ip', 'dst_ip')},
                        'src_port': traffic.get('src_port', 0),
                        'dst_port': traffic.get('dst_port', 0),
                    },
                    source = 'wazuh',
                )

                processed += 1
            except Exception as e:
                logger.warning(f"[Wazuh] Alert traitement erreur: {e}")
                continue

        except Exception as e:
            logger.warning(f"[Wazuh] Alert erreur: {e}")
            continue

    return f"{processed} alertes traitées"