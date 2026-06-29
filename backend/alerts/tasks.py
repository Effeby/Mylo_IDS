import logging
import requests
from celery import shared_task
from django.conf import settings
from .wazuh_client import WazuhClient
from .wazuh_rules import get_alert_class, is_rule_id_mapped, CLASS_DEFAULTS, NORMAL, SUSPICIOUS

logger = logging.getLogger(__name__)

# IPs de l'infrastructure Mylo — jamais alertées entre elles
INFRASTRUCTURE_IPS = {
    "173.212.241.228",
    "172.16.1.94",
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.4",
}

INFRASTRUCTURE_PAIRS = {
    ("173.212.241.228", "172.16.1.94"),
    ("172.16.1.94", "173.212.241.228"),
    ("10.0.0.2", "172.16.1.94"),
    ("172.16.1.94", "10.0.0.2"),
    ("10.0.0.2", "10.0.0.4"),
    ("10.0.0.4", "10.0.0.2"),
}


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
        # Fenêtre de 3 minutes + plafond de 50 docs : évite de repolling en
        # boucle les mêmes vieilles alertes à chaque cycle (flood).
        alerts = client.get_alerts(limit=50, since_minutes=3)
    except Exception as e:
        logger.error(f"[Wazuh] Fetch erreur: {e}")
        return f"Erreur: {e}"

    if not alerts:
        return "0 alertes"

    # Filet de sécurité — get_alerts() applique déjà size=50 côté OpenSearch.
    alerts = alerts[:50]

    from accounts.models import Organisation
    from .models import IDSSettings, Alert, WhitelistedIP
    org = Organisation.objects.first()
    if not org:
        return "Pas d'organisation"

    ids_settings = IDSSettings.get(org)

    processed = 0
    skipped_duplicates = 0
    for alert in alerts:
        try:
            wazuh_alert_id = alert.get('_id')

            # Déduplication — ce document OpenSearch a-t-il déjà été persisté
            # par un cycle de polling précédent ?
            if wazuh_alert_id and Alert.objects.filter(
                organisation=org, wazuh_alert_id=wazuh_alert_id
            ).exists():
                skipped_duplicates += 1
                continue

            agent      = alert.get('agent', {})
            rule       = alert.get('rule', {})
            data_field = alert.get('data', {})

            src_ip = (
                data_field.get('srcip') or
                data_field.get('src_ip') or
                agent.get('ip', '0.0.0.0')
            )
            dst_ip = data_field.get('dstip') or data_field.get('dst_ip') or '172.16.1.1'

            # Skip silencieux pour le trafic infra interne (au-dessus de la
            # whitelist admin — ne doit pas interférer avec elle)
            if (src_ip, dst_ip) in INFRASTRUCTURE_PAIRS:
                continue
            if src_ip in INFRASTRUCTURE_IPS and dst_ip in INFRASTRUCTURE_IPS:
                continue

            is_whitelisted = WhitelistedIP.objects.filter(organisation=org, ip_address__in=[src_ip, dst_ip]).exists()

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

            rule_id    = int(rule.get('id', 0))
            rule_level = int(rule.get('level', 0))

            # Alerte Wazuh sans aucune donnée de flux réseau : XGBoost n'a aucun
            # signal discriminant dans ce cas, on ne l'appelle pas et on classe
            # uniquement via le mapping rule_id -> classe Mylo. Si le rule_id est
            # inconnu, on ignore l'alerte plutôt que de risquer un faux positif ML.
            no_network_features = (
                traffic['src_bytes'] == 0 and
                traffic['dst_bytes'] == 0 and
                traffic['src_port']  == 0 and
                traffic['dst_port']  == 0
            )

            try:
                if no_network_features:
                    if not is_rule_id_mapped(rule_id):
                        continue

                    mylo_class = get_alert_class(rule_id)
                    defaults   = CLASS_DEFAULTS[mylo_class]
                    prediction = {
                        'attack_type':       mylo_class,
                        'is_attack':         mylo_class != NORMAL,
                        'attack_confidence': 0.90,
                        'binary_confidence': 0.90,
                        'binary_label':      'Attack' if mylo_class != NORMAL else 'Normal',
                        'severity':          defaults['severity'],
                        'alert_status':      'Nouvelle' if mylo_class != NORMAL else 'Normal',
                    }
                else:
                    # Call FastAPI ML predict endpoint
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
                from .views import (
                    compute_detection_score, compute_cvss_severity,
                    get_asset_for_ip, WHITELIST_BYPASS_CONFIDENCE, auto_block_ip
                )

                # IP whitelistée → on ignore seulement les alertes faibles ou
                # Normal. Une vraie attaque à forte confiance crée quand même
                # l'alerte (tag 'whitelisted_source') pour détecter une IP de
                # confiance compromise plutôt que de l'ignorer silencieusement.
                if is_whitelisted and (
                    not prediction.get('is_attack', False)
                    or prediction.get('attack_type', 'Normal') == 'Normal'
                    or prediction.get('attack_confidence', 0) < WHITELIST_BYPASS_CONFIDENCE
                ):
                    continue

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

                alert = Alert.objects.create(
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
                        **({'tags': ['whitelisted_source']} if is_whitelisted else {}),
                    },
                    source = 'wazuh',
                    wazuh_alert_id = wazuh_alert_id,
                )

                processed += 1

                # Blocage automatique — même logique que pour les analyses
                # scapy (AnalyzeView), appliquée ici aux alertes Wazuh.
                if (
                    getattr(settings, 'MYLO_AUTO_BLOCK', False)
                    and ids_settings.auto_block_enabled
                    and alert.binary_confidence >= ids_settings.auto_block_threshold
                    and alert.attack_type != 'Normal'
                ):
                    try:
                        auto_block_ip(org, src_ip, f"Auto-block Wazuh: {alert.attack_type}")
                    except Exception as block_err:
                        logger.warning(f"[Wazuh] Auto-block erreur pour {src_ip}: {block_err}")
            except Exception as e:
                logger.warning(f"[Wazuh] Alert traitement erreur: {e}")
                continue

        except Exception as e:
            logger.warning(f"[Wazuh] Alert erreur: {e}")
            continue

    return f"{processed} alertes traitées, {skipped_duplicates} doublons ignorés"