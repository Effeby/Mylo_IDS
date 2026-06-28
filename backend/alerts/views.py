from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from django.db.models import Count
import requests
import random
import threading
from django.conf import settings
from rest_framework.exceptions import ValidationError
from .models import Alert, Asset, BlacklistedIP, WhitelistedIP, IDSSettings, NetworkLog
from alerts.baseline import BaselineManager
from accounts.models import AuditLog
from alerts.opnsense_client import OPNsenseClient
from .wazuh_client import WazuhClient
from core.validators import validate_ip, validate_ip_or_cidr, validate_safe_text


# ─── HELPERS TENANT ──────────────────────────────────────────────────────────
def get_org(request):
    return getattr(request.user, 'organisation', None)

def tenant_qs(model, request):
    if getattr(request.user, 'is_super_admin', False):
        return model.objects.all()
    return model.objects.filter(organisation=get_org(request))


# ─── BLOCAGE AUTO — délégation à l'agent capture ─────────────────────────────
def auto_block_ip(org, ip, raison):
    """
    Bloque une IP sur OPNsense suite à une détection automatique.

    Django tourne désormais sur Contabo et ne peut plus atteindre OPNsense
    (172.16.1.1, réseau privé) directement. Si MYLO_AUTO_BLOCK est activé et
    qu'un agent de capture est configuré (CAPTURE_AGENT_URL), on délègue le
    blocage à cet agent — il tourne lui sur le réseau local (ex: BanqueAdmin
    10.0.0.2) et peut donc atteindre OPNsense.
    Sinon, on retombe sur l'appel direct historique (utile en lab où Django
    et OPNsense sont sur le même réseau).
    """
    agent_url = getattr(settings, 'CAPTURE_AGENT_URL', '')
    if getattr(settings, 'MYLO_AUTO_BLOCK', False) and agent_url:
        headers = {}
        secret = getattr(settings, 'CAPTURE_AGENT_SECRET', '')
        if secret:
            headers['X-Capture-Secret'] = secret
        try:
            r = requests.post(
                f"{agent_url.rstrip('/')}/block-ip/",
                json={'ip': ip},
                headers=headers,
                timeout=5,
            )
            return r.json()
        except Exception as e:
            return {'success': False, 'message': f"Agent capture inaccessible: {e}"}

    try:
        opnsense = OPNsenseClient(organisation=org)
        return opnsense.bloquer_ip(ip, raison=raison)
    except Exception as e:
        return {'success': False, 'message': str(e)}


# ─── ENVOIE DE MAILS ─────────────────────────────────────────────
def send_alert_email(alert, organisation=None):
    """Envoie un email d'alerte à l'organisation concernée."""
    def _send():
        try:
            from django.template.loader import render_to_string
            from django.core.mail import EmailMultiAlternatives

            s = IDSSettings.get(organisation)

            if not s.notif_enabled:
                return
            if not s.notif_email_enabled:
                return
            if not s.notif_email_address:
                return

            # Vérifier sévérité minimale
            severity_order = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
            alert_level = severity_order.get(alert.severity, 0)
            min_level   = severity_order.get(s.notif_email_min_severity, 2)
            if alert_level < min_level:
                return

            # Pour les alertes Behavioral : seulement si score >= 7 (CRITICAL)
            is_behavioral = alert.attack_type == 'Behavioral'
            if is_behavioral and alert.detection_score < 7.0:
                return

            org_name = organisation.name if organisation else 'Mylo IPS'

            # Couleurs selon sévérité
            severity_colors = {
                'CRITICAL': '#EF4444',
                'HIGH':     '#F97316',
                'MEDIUM':   '#EAB308',
                'LOW':      '#22C55E',
            }
            severity_bgs = {
                'CRITICAL': 'rgba(239,68,68,0.15)',
                'HIGH':     'rgba(249,115,22,0.15)',
                'MEDIUM':   'rgba(234,179,8,0.15)',
                'LOW':      'rgba(34,197,94,0.15)',
            }

            # Données pour le template
            features = alert.features or {}
            anomalies = features.get('anomalies', [])
            anomaly_detail = ' · '.join([
                a.get('detail', '') for a in anomalies[:3]
            ]) if anomalies else '—'

            context = {
                'org_name':         org_name,
                'attack_type':      alert.attack_type,
                'severity':         alert.severity,
                'severity_color':   severity_colors.get(alert.severity, '#94A3B8'),
                'severity_bg':      severity_bgs.get(alert.severity, 'rgba(100,116,139,0.15)'),
                'border_color':     severity_colors.get(alert.severity, '#94A3B8'),
                'src_ip':           alert.src_ip,
                'dst_ip':           alert.dst_ip or '—',
                'confidence':       round(alert.attack_confidence * 100, 1),
                'final_score':      round(alert.final_score, 1),
                'anomaly_score':    round(alert.detection_score, 1),
                'anomaly_detail':   anomaly_detail,
                'asset_name':       alert.asset_name or '—',
                'asset_criticality': alert.asset_criticality,
                'detected_at':      alert.detected_at.strftime('%d/%m/%Y à %H:%M:%S'),
                'is_behavioral':    is_behavioral,
            }

            html = render_to_string('emails/alert.html', context)

            subject = (
                f"{'🔍' if is_behavioral else '🚨'} [{org_name}] "
                f"{'Anomalie' if is_behavioral else 'Alerte'} {alert.severity} — "
                f"{alert.attack_type} depuis {alert.src_ip}"
            )

            text = (
                f"{'Anomalie comportementale' if is_behavioral else 'Alerte'} {alert.severity} — {alert.attack_type}\n"
                f"IP Source : {alert.src_ip}\n"
                f"{'Score : ' + str(round(alert.detection_score,1)) + '/10' if is_behavioral else 'Confiance : ' + str(round(alert.attack_confidence*100,1)) + '%'}\n"
                f"Détectée : {alert.detected_at.strftime('%d/%m/%Y à %H:%M:%S')}\n"
                f"-- Mylo IPS · mylo-ids.site"
            )

            msg = EmailMultiAlternatives(
                subject=subject,
                body=text,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[s.notif_email_address],
            )
            msg.attach_alternative(html, "text/html")
            msg.send()
            print(f"  ✉  Email {'behavioral' if is_behavioral else 'alerte'} envoyé à {s.notif_email_address}")

        except Exception as e:
            print(f"  ✗ Email erreur: {e}")

    threading.Thread(target=_send, daemon=True).start()


# ─── TELEGRAM ────────────────────────────────────────────────────────────────
#def send_telegram(message: str, organisation=None):
#    def _send():
#        try:
#            s = IDSSettings.get(organisation)
#            token   = s.notif_telegram_token or '8649586999:AAGJ1TtxfnRQ02doY4SYV00TmYfvw1JnAx4'
#            chat_id = s.notif_telegram_chat  or '5225530595'
#            if not token or not chat_id:
#                return
#            requests.post(
#                f'https://api.telegram.org/bot{token}/sendMessage',
 #               json={'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML'},
#                timeout=5,
#            )
#        except Exception:
 #           pass
#    threading.Thread(target=_send, daemon=True).start()

def send_telegram(message: str, organisation=None):
    def _send():
        try:
            s = IDSSettings.get(organisation)
            
            # Vérifier que Telegram est activé pour cette org
            if not s.notif_telegram_enabled:
                return
            if not s.notif_enabled:
                return
                
            token   = s.notif_telegram_token
            chat_id = s.notif_telegram_chat
            
            # Ne pas envoyer si pas configuré
            if not token or not chat_id:
                return
                
            requests.post(
                f'https://api.telegram.org/bot{token}/sendMessage',
                json={'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML'},
                timeout=5,
            )
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


# ─── MAPS ─────────────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    'Normal':      'LOW',
    'DoS':         'HIGH',
    'DDoS':        'HIGH',
    'Probe':       'MEDIUM',
    'R2L':         'CRITICAL',
    'U2R':         'CRITICAL',
    'BruteForce':  'HIGH',
    'WebAttack':   'CRITICAL',
    'Botnet':      'CRITICAL',
    'Infiltration':'CRITICAL',
}

PROTOCOLS = ['TCP', 'UDP', 'ICMP']

ASSET_CRITICALITY_MULTIPLIER = {
    'PUBLIC': 0.8,
    'INTERNAL': 1.0,
    'CRITICAL': 1.5,
}

SEVERITY_THRESHOLDS = [
    (9.0, 'CRITICAL'),
    (7.0, 'HIGH'),
    (4.0, 'MEDIUM'),
    (0.0, 'LOW'),
]

ATTACK_WEIGHTS = {
    'U2R':                 1.5,
    'PrivilegeEscalation': 1.5,
    'R2L':                 1.3,
    'Infiltration':        1.3,
    'Malware':             1.4,
    'WebAttack':           1.2,
    'Botnet':              1.2,
    'BruteForce':          1.1,
    'DoS':                 1.1,
    'DDoS':                1.1,
    'Probe':               0.8,
    'PortScan':            0.8,
    'Reconnaissance':      0.8,
    'Behavioral':          0.9,
    'Suspicious':          0.9,
    'Normal':              0.0,
}

# Confiance minimale pour qu'une IP whitelistée déclenche quand même une
# alerte. Sous ce seuil (ou si Normal), l'alerte reste ignorée comme avant —
# au-dessus, on crée l'alerte avec le tag 'whitelisted_source' car une IP de
# confiance qui se comporte comme un attaquant à forte confiance est plus
# probablement compromise qu'un faux positif.
WHITELIST_BYPASS_CONFIDENCE = 0.75


def get_asset_for_ip(org, ip):
    if not org or not ip:
        return None
    return Asset.objects.filter(organisation=org, ip_address=ip).first()


def compute_detection_score(prediction: dict) -> float:
    # Si c'est Normal, le score de détection est 0
    if not prediction.get('is_attack', False):
        return 0.0
    return min(max(float(prediction.get('attack_confidence', 0)) * 10, 0.0), 10.0)


def compute_cvss_severity(
    detection_score: float,
    criticality: int = 2,
    attack_type: str = 'Normal',
    asset_multiplier: float = None,
):
    if detection_score == 0.0 or attack_type == 'Normal':
        return 'LOW', 0.0, 1.0

    if asset_multiplier is None:
        from .models import Asset
        asset_multiplier = Asset.CRITICALITY_MULTIPLIER.get(criticality, 1.0)

    attack_weight = ATTACK_WEIGHTS.get(attack_type, 1.0)
    final_score   = min(detection_score * asset_multiplier * attack_weight, 10.0)

    for threshold, label in SEVERITY_THRESHOLDS:
        if final_score >= threshold:
            return label, round(final_score, 2), asset_multiplier

    return 'LOW', round(final_score, 2), asset_multiplier

def discover_assets_from_traffic(org, lookback_hours=24):
    if not org:
        return []
    return Asset.discover_from_traffic(org, lookback_hours=lookback_hours)


def discover_assets_by_arp(target_ip):
    print(f"[AssetDiscovery] Début scan ARP sur {target_ip}")
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as e:
        raise RuntimeError('Scapy non installé. Installez scapy pour activer le scan ARP.') from e

    arp = ARP(pdst=target_ip)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for _, received in result:
        client = {'ip': received.psrc, 'mac': received.hwsrc}
        print(f"[AssetDiscovery] ARP trouvé: {client}")
        clients.append(client)
    print(f"[AssetDiscovery] Scan ARP terminé, {len(clients)} hôtes découverts")
    return clients


def persist_arp_assets(org, clients):
    from django.utils import timezone

    assets = []
    for client in clients:
        asset, created = Asset.objects.update_or_create(
            organisation=org,
            ip_address=client['ip'],
            defaults={
                'mac_address': client['mac'],
                'hostname': '',
                'name': '',
                'segment': '',
                'criticality': 'INTERNAL',
                'last_seen': timezone.now(),
            }
        )
        print(f"[AssetDiscovery] Persist actif {asset.ip_address} created={created}")
        assets.append(asset)
    print(f"[AssetDiscovery] {len(assets)} actifs persistés")
    return assets


SIMULATED_SRC_IPS = [
    '192.168.1.10', '192.168.1.25', '192.168.2.5',
    '10.0.0.15',    '10.0.1.100',   '172.16.0.50',
    '203.0.113.42', '198.51.100.7', '185.220.101.5',
    '192.168.10.55','10.10.10.1',   '172.16.5.200',
]
SIMULATED_DST_IPS = [
    '10.0.0.1', '10.0.0.2', '192.168.1.1',
    '172.16.0.1', '10.0.0.254',
]


def trigger_river_learning(features: dict, true_label: str):
    def _learn():
        try:
            from actions.views import _get_model, _river_state, _save_river, XGB_FEATURES, ALL_CLASSES
            if true_label not in ALL_CLASSES:
                return
            model = _get_model()
            x = {k: float(features.get(k, 0)) for k in XGB_FEATURES}
            y_pred = model.predict_one(x)
            if y_pred is not None:
                _river_state['metric'].update(true_label, y_pred)
                if 'report' in _river_state:
                    _river_state['report'].update(true_label, y_pred)
            model.learn_one(x, true_label)
            _river_state['total'] += 1
            _river_state['counts'][true_label] = _river_state['counts'].get(true_label, 0) + 1
            from django.utils import timezone
            _river_state['history'].append({
                'total':    _river_state['total'],
                'accuracy': round(_river_state['metric'].get(), 4),
                'label':    true_label,
                'correct':  y_pred == true_label,
                'time':     timezone.now().isoformat(),
            })
            _save_river()
            if _river_state['total'] % 5 == 0:
                try:
                    from actions.models import RiverMetrics
                    RiverMetrics.objects.create(
                        accuracy      = round(_river_state['metric'].get(), 4),
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
            accuracy = round(_river_state['metric'].get(), 4)
            correct  = y_pred == true_label
            print(f"  🧠 River [{true_label:12s}] "
                  f"{'✓' if correct else '✗'} "
                  f"acc:{accuracy:.3f} total:{_river_state['total']}")
            try:
                requests.post(f"{settings.MYLO_FASTAPI_URL}/reload-river", timeout=3)
            except Exception:
                pass
        except Exception as e:
            print(f"  ✗ River erreur: {e}")
    threading.Thread(target=_learn, daemon=True).start()


# ─── LISTE DES ALERTES ────────────────────────────────────────────────────────
class AlertListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        limit         = int(request.query_params.get('limit', 50))
        attack_type   = request.query_params.get('type') or request.query_params.get('attack_type')
        severity      = request.query_params.get('severity')
        src_ip        = request.query_params.get('ip')
        source        = request.query_params.get('source')
        status_filter = request.query_params.get('status')
        date_from     = request.query_params.get('date_from')
        date_to       = request.query_params.get('date_to')

        qs = tenant_qs(Alert, request)
        if attack_type:   qs = qs.filter(attack_type=attack_type)
        if severity:      qs = qs.filter(severity=severity)
        if src_ip:        qs = qs.filter(src_ip__icontains=src_ip)
        if source:        qs = qs.filter(source=source)
        if status_filter: qs = qs.filter(status=status_filter)
        if date_from:     qs = qs.filter(detected_at__date__gte=date_from)
        if date_to:       qs = qs.filter(detected_at__date__lte=date_to)

        return Response([_serialize_alert(a) for a in qs[:limit]])


# ─── DÉTAIL D'UNE ALERTE ──────────────────────────────────────────────────────
class AlertDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            a = tenant_qs(Alert, request).get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Alerte introuvable'}, status=404)
        return Response(_serialize_alert(a))

    def patch(self, request, pk):
        try:
            a = tenant_qs(Alert, request).get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Alerte introuvable'}, status=404)

        new_status = request.data.get('status')
        if not new_status:
            return Response({'error': 'Champ status manquant'}, status=400)

        a.status = new_status
        a.save()

        river_triggered = False

        if new_status == 'false_positive' and a.features:
            trigger_river_learning(a.features, 'Normal')
            river_triggered = True
            s_fp = IDSSettings.get(a.organisation)
            if a.src_ip and a.binary_confidence < s_fp.binary_threshold:
                WhitelistedIP.objects.get_or_create(
                    organisation=get_org(request),
                    ip_address=a.src_ip,
                    defaults={
                        'description': f'Faux positif — {a.attack_type} ({a.binary_confidence:.2f})',
                    }
                )
        elif new_status == 'confirmed' and a.features:
            true_label = request.data.get('true_label', a.attack_type)
            trigger_river_learning(a.features, a.attack_type)
            river_triggered = True

        return Response({
            'message':         'Alerte mise à jour',
            'status':          new_status,
            'river_triggered': river_triggered,
        })


# ─── STATS ────────────────────────────────────────────────────────────────────
class AlertStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = tenant_qs(Alert, request)
        total      = qs.count()
        attacks    = qs.filter(is_attack=True).count()
        by_type    = dict(qs.filter(is_attack=True).values_list('attack_type').annotate(c=Count('id')).values_list('attack_type', 'c'))
        by_severity = dict(qs.filter(is_attack=True).values_list('severity').annotate(c=Count('id')).values_list('severity', 'c'))
        false_positives = qs.filter(status='false_positive').count()
        under_review    = qs.filter(status='under_review').count()
        ignored         = qs.filter(status='ignored').count()
        new_alerts      = qs.filter(status='new', is_attack=True).count()
        top_ips = list(qs.filter(is_attack=True).values('src_ip').annotate(count=Count('id')).order_by('-count')[:5])

        return Response({
            'total':           total,
            'attacks':         attacks,
            'normal':          total - attacks,
            'new_alerts':      new_alerts,
            'false_positives': false_positives,
            'under_review':    under_review,
            'ignored':         ignored,
            'attack_rate':     round(attacks / total, 4) if total > 0 else 0,
            'by_type':         by_type,
            'by_severity':     by_severity,
            'top_ips':         top_ips,
        })


# ─── ANALYSE TRAFIC → FASTAPI → BDD ──────────────────────────────────────────
class AnalyzeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        traffic_data = request.data
        org          = get_org(request)
        src_ip = traffic_data.get('src_ip') or random.choice(SIMULATED_SRC_IPS)
        dst_ip = traffic_data.get('dst_ip') or random.choice(SIMULATED_DST_IPS)

        is_whitelisted = WhitelistedIP.objects.filter(organisation=org, ip_address__in=[src_ip, dst_ip]).exists()

        try:
            payload = {**traffic_data, 'src_ip': src_ip, 'dst_ip': dst_ip}
            resp = requests.post(
                f"{settings.MYLO_FASTAPI_URL}/predict",
                json=payload, timeout=5
            )
            prediction = resp.json()
        except Exception as e:
            return Response({'error': f'FastAPI indisponible: {e}'}, status=503)

        # IP whitelistée → on ignore seulement les alertes faibles ou Normal.
        # Une vraie attaque à forte confiance crée quand même l'alerte (cf.
        # tag 'whitelisted_source' plus bas) pour détecter une IP de confiance
        # compromise plutôt que de l'ignorer silencieusement.
        if is_whitelisted and (
            not prediction.get('is_attack', False)
            or prediction.get('attack_type', 'Normal') == 'Normal'
            or prediction.get('attack_confidence', 0) < WHITELIST_BYPASS_CONFIDENCE
        ):
            return Response({
                'is_attack': False, 'binary_label': 'Normal',
                'binary_confidence': 0.0, 'attack_type': 'Normal',
                'attack_confidence': 1.0, 'severity': 'LOW',
                'alert_status': 'Ignorée', 'src_ip': src_ip,
                'dst_ip': dst_ip, 'whitelisted': True,
            })

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
            protocol          = traffic_data.get('protocol', random.choice(PROTOCOLS)),
            src_bytes         = traffic_data.get('src_bytes', 0),
            dst_bytes         = traffic_data.get('dst_bytes', 0),
            duration          = traffic_data.get('duration', 0),
            status            = db_status,
            features          = {
                **{k: v for k, v in traffic_data.items() if k not in ('src_ip', 'dst_ip')},
                'src_port': traffic_data.get('src_port', 0),
                'dst_port': traffic_data.get('dst_port', 0),
                **({'tags': ['whitelisted_source']} if is_whitelisted else {}),
            },
            source = traffic_data.get('source', 'scapy'),
        )

        if prediction.get('is_attack') and severity in ('HIGH', 'CRITICAL', 'MEDIUM'):
            s = IDSSettings.get(org)
            if s.notif_enabled:
                severity_order = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
                alert_level    = severity_order.get(severity, 0)
                min_level      = severity_order.get(s.notif_min_severity, 1)
                
                if alert_level >= min_level:
                    org_name = org.name if org else 'Mylo IPS'
                    
                    # Telegram — seulement si activé pour cette org
                    if s.notif_telegram_enabled:
                        send_telegram(
                            f"🚨 <b>{org_name} — Mylo IPS</b>\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"⚠️ <b>Type</b>     : {prediction.get('attack_type')}\n"
                            f"🔴 <b>Sévérité</b> : {severity}\n"
                            f"🌐 <b>IP Source</b> : <code>{src_ip}</code>\n"
                            f"🎯 <b>IP Dest</b>   : <code>{dst_ip}</code>\n"
                            f"📊 <b>Score</b>     : {final_score:.1f}/10\n"
                            f"🕐 <b>Heure</b>     : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"🔒 Mylo IPS Security Center",
                            organisation=org,
                        )
                    
                    # Email — seulement si activé pour cette org  
                    if s.notif_email_enabled:
                        send_alert_email(alert, organisation=org)

        action = None
        ids = IDSSettings.get(org)
        if (ids.auto_block_enabled
                and prediction.get('is_attack')
                and prediction.get('binary_confidence', 0) >= ids.auto_block_threshold
                and alert_status == 'Nouvelle'):
            rule_info = traffic_data.get('rule') or prediction.get('rule') or {}
            if isinstance(rule_info, dict):
                rule_label = rule_info.get('name') or rule_info.get('id') or rule_info.get('title') or ''
            else:
                rule_label = str(rule_info)
            if not rule_label:
                rule_label = 'non précisée'

            block_result = None
            if ids.opnsense_enabled:
                block_result = auto_block_ip(
                    org, src_ip,
                    raison=f"Auto — {prediction.get('attack_type')} ({prediction.get('binary_confidence'):.2f})"
                )
            else:
                block_result = {
                    'success': False,
                    'message': 'OPNsense désactivé pour cette organisation'
                }

            if block_result.get('success'):
                BlacklistedIP.objects.get_or_create(
                    organisation=org,
                    ip_address=src_ip,
                    defaults={
                        'reason':     f"Auto — {prediction.get('attack_type')} ({prediction.get('binary_confidence'):.2f})",
                        'blocked_by': 'auto',
                    }
                )
                alert.action_taken = 'auto_blocked'
                alert.save()
                action = 'blocked'
            else:
                AuditLog.log(
                    action='ip_block',
                    user=request.user,
                    organisation=org,
                    description=(
                        f"Échec du blocage auto OPNsense de {src_ip} pour l'alerte {alert.id} "
                        f"({prediction.get('attack_type')} {prediction.get('binary_confidence'):.2f}), règle: {rule_label}. "
                        f"Erreur: {block_result.get('message')}"
                    ),
                    object_type='Alert',
                    object_id=alert.id,
                    object_repr=str(alert),
                    success=False,
                    extra_data={
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'attack_type': prediction.get('attack_type'),
                        'binary_confidence': prediction.get('binary_confidence'),
                        'rule': rule_info,
                        'opnsense': block_result,
                    }
                )

            if block_result.get('success'):
                AuditLog.log(
                    action='ip_block',
                    user=request.user,
                    organisation=org,
                    description=(
                        f"Blocage auto OPNsense de {src_ip} réalisé pour l'alerte {alert.id} "
                        f"({prediction.get('attack_type')} {prediction.get('binary_confidence'):.2f}), règle: {rule_label}."
                    ),
                    object_type='Alert',
                    object_id=alert.id,
                    object_repr=str(alert),
                    extra_data={
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'attack_type': prediction.get('attack_type'),
                        'binary_confidence': prediction.get('binary_confidence'),
                        'rule': rule_info,
                        'opnsense': block_result,
                    }
                )

        # ── Analyse comportementale + Corrélation (non bloquant) ─────
        def _post_analysis():
            update_ip_baseline(org, {
                **traffic_data,
                'src_ip':  src_ip,
                'dst_ip':  dst_ip,
                'dst_port': traffic_data.get('dst_port', 0),
            }, is_attack=prediction.get('is_attack', False))
            # Corrélation uniquement sur les vraies attaques
            if prediction.get('is_attack', False):
                correlate_alerts(org, alert)
        threading.Thread(target=_post_analysis, daemon=True).start()
        # ─────────────────────────────────────────────────────────────

        return Response({
            **prediction,
            'alert_id':         alert.id,
            'src_ip':           src_ip,
            'dst_ip':           dst_ip,
            'severity':         severity,
            'asset_name':       alert.asset_name,
            'asset_criticality': alert.asset_criticality,
            'final_score':      alert.final_score,
            'alert_status':     alert_status,
            'action':           action,
            'whitelisted_source': is_whitelisted,
        })


# ─── ASSETS / INVENTAIRE DES ÉQUIPEMENTS ─────────────────────────────────────
class AssetListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.can_manage_users and not request.user.can_configure_ids:
            return Response({'error': 'Permission insuffisante'}, status=403)
        qs = tenant_qs(Asset, request)
        return Response([{
            'id':           a.id,
            'ip_address':   a.ip_address,
            'mac_address':  a.mac_address,
            'hostname':     a.hostname,
            'name':         a.name,
            'label':        a.label,
            'os_type':      a.os_type,
            'open_ports':   a.open_ports,
            'services':     a.services,
            'segment':      a.segment,
            'criticality':  a.criticality,
            'criticality_label': a.criticality_label,
            'is_authorized': a.is_authorized,
            'multiplier':   a.multiplier,
            'last_seen':    a.last_seen.isoformat() if a.last_seen else None,
            'discovered_at': a.discovered_at.isoformat(),
            'updated_at':   a.updated_at.isoformat(),
        } for a in qs])

    def post(self, request):
        if not request.user.can_manage_users and not request.user.can_configure_ids:
            return Response({'error': 'Permission insuffisante'}, status=403)
        d = request.data
        try:
            ip_address = validate_ip(d.get('ip_address'))
        except ValidationError as e:
            return Response({'error': str(e.detail[0]) if isinstance(e.detail, list) else str(e)}, status=400)
        asset, created = Asset.objects.get_or_create(
            organisation=get_org(request),
            ip_address=ip_address,
            defaults={
                'mac_address': d.get('mac_address', ''),
                'hostname':    d.get('hostname', ''),
                'name':        d.get('name', ''),
                'segment':     d.get('segment', ''),
                'criticality': d.get('criticality', 'INTERNAL'),
                'last_seen':   d.get('last_seen'),
            }
        )
        if not created:
            updated = False
            for field in ['mac_address', 'hostname', 'name', 'segment', 'criticality', 'last_seen']:
                if field in d and getattr(asset, field) != d[field]:
                    setattr(asset, field, d[field])
                    updated = True
            if updated:
                asset.save()
        return Response({'id': asset.id, 'created': created})


class AssetDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_asset(self, pk, request):
        try:
            asset = Asset.objects.get(pk=pk)
            if not request.user.is_super_admin and asset.organisation != get_org(request):
                return None
            return asset
        except Asset.DoesNotExist:
            return None

    def patch(self, request, pk):
        if not request.user.can_manage_users and not request.user.can_configure_ids:
            return Response({'error': 'Permission insuffisante'}, status=403)
        asset = self._get_asset(pk, request)
        if not asset:
            return Response({'error': 'Actif introuvable'}, status=404)
        for field in ['mac_address', 'hostname', 'name', 'label', 'segment', 'criticality', 'last_seen', 'is_authorized', 'os_type', 'open_ports', 'services']:
            if field in request.data:
                setattr(asset, field, request.data[field])
        asset.save()
        return Response({'message': 'Actif mis à jour'})


class AssetDiscoverView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        org       = get_org(request)
        target_ip = request.data.get('target_ip')

        if not target_ip:
            return Response(
                {'error': 'Fournir target_ip (ex: 192.168.1.0/24)'},
                status=400
            )
        try:
            target_ip = validate_ip_or_cidr(target_ip)
        except ValidationError as e:
            return Response({'error': str(e.detail[0]) if isinstance(e.detail, list) else str(e)}, status=400)

        # La découverte réseau (ARP/Nmap) nécessite d'être sur le réseau local
        # de la cible. Le serveur Django (ex: Contabo) ne l'est pas forcément
        # → on délègue à l'agent capture qui tourne lui sur le réseau local.
        agent_unavailable_msg = (
            "La découverte réseau n'est disponible que depuis l'agent local. "
            "Assurez-vous que l'agent capture est actif."
        )
        agent_url = getattr(settings, 'CAPTURE_AGENT_URL', '')
        if not agent_url:
            return Response({'error': agent_unavailable_msg}, status=503)

        headers = {}
        secret = getattr(settings, 'CAPTURE_AGENT_SECRET', '')
        if secret:
            headers['X-Capture-Secret'] = secret

        try:
            resp = requests.post(
                f"{agent_url.rstrip('/')}/discover/",
                json={'cidr': target_ip},
                headers=headers,
                timeout=60,
            )
            resp.raise_for_status()
            devices = resp.json().get('devices', [])
        except Exception:
            return Response({'error': agent_unavailable_msg}, status=503)

        try:
            from discovery import persist_discovered_devices
            assets = persist_discovered_devices(org, devices)
        except Exception as e:
            return Response(
                {'error': f"Erreur découverte : {e}"},
                status=500
            )

        return Response([{
            'id':           a.id,
            'ip_address':   a.ip_address,
            'mac_address':  a.mac_address,
            'hostname':     a.hostname,
            'name':         a.name,
            'label':        a.label,
            'os_type':      a.os_type,
            'open_ports':   a.open_ports,
            'services':     a.services,
            'criticality':  a.criticality,
            'criticality_label': a.criticality_label,
            'is_authorized': a.is_authorized,
            'last_seen':    a.last_seen.isoformat() if a.last_seen else None,
        } for a in assets])

class BlacklistView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ips = tenant_qs(BlacklistedIP, request).filter(is_active=True)
        return Response([{
            'id':          ip.id,
            'ip_address':  ip.ip_address,
            'reason':      ip.reason,
            'blocked_by':  ip.blocked_by,
            'alert_count': ip.alert_count,
            'created_at':  ip.created_at.isoformat(),
        } for ip in ips])

    def post(self, request):
        try:
            ip     = validate_ip(request.data.get('ip_address'))
            reason = validate_safe_text(
                request.data.get('reason', 'Bloqué manuellement'),
                max_length=255, field_name='reason',
            )
        except ValidationError as e:
            return Response({'error': str(e.detail[0]) if isinstance(e.detail, list) else str(e)}, status=400)
        org = get_org(request)
        obj, created = BlacklistedIP.objects.get_or_create(
            organisation=org,
            ip_address=ip,
            defaults={'reason': reason, 'blocked_by': 'manual'}
        )
        if not created:
            obj.is_active = True
            obj.reason = reason
            obj.blocked_by = 'manual'
            obj.save()

        ids = IDSSettings.get(org)
        block_result = None
        if ids.opnsense_enabled:
            try:
                opnsense = OPNsenseClient(organisation=org)
                block_result = opnsense.bloquer_ip(ip, raison=reason)
            except Exception as e:
                block_result = {'success': False, 'message': str(e)}
        else:
            block_result = {'success': False, 'message': 'OPNsense désactivé pour cette organisation'}

        AuditLog.log(
            action='ip_block',
            user=request.user,
            organisation=org,
            description=(
                f"Blocage manuel de {ip} ({reason}) - "
                f"Résultat: {block_result.get('message')}"
            ),
            object_type='BlacklistedIP',
            object_id=obj.id,
            object_repr=str(obj),
            extra_data={
                'ip_address': ip,
                'reason': reason,
                'opnsense': block_result,
            }
        )

        return Response({
            'message': f'{ip} blacklistée',
            'created': created,
            'opnsense': block_result,
        })

    def delete(self, request):
        try:
            ip = validate_ip(request.data.get('ip_address'))
        except ValidationError as e:
            return Response({'error': str(e.detail[0]) if isinstance(e.detail, list) else str(e)}, status=400)
        org = get_org(request)
        tenant_qs(BlacklistedIP, request).filter(ip_address=ip).update(is_active=False)

        ids = IDSSettings.get(org)
        unblock_result = None
        if ids.opnsense_enabled:
            try:
                opnsense = OPNsenseClient(organisation=org)
                unblock_result = opnsense.debloquer_ip(ip)
            except Exception as e:
                unblock_result = {'success': False, 'message': str(e)}
        else:
            unblock_result = {'success': False, 'message': 'OPNsense désactivé pour cette organisation'}

        AuditLog.log(
            action='ip_unblock',
            user=request.user,
            organisation=org,
            description=(
                f"Déblocage manuel de {ip} - Résultat: {unblock_result.get('message')}"
            ),
            object_type='BlacklistedIP',
            object_id='',
            object_repr=ip,
            extra_data={
                'ip_address': ip,
                'opnsense': unblock_result,
            }
        )
        return Response({
            'message': f'{ip} débloquée',
            'opnsense': unblock_result,
        })


# ─── HELPER ───────────────────────────────────────────────────────────────────
def _serialize_alert(a):
    features = a.features or {}
    return {
        'id':                a.id,
        'attack_type':       a.attack_type,
        'severity':          a.severity,
        'is_attack':         bool(a.is_attack),
        'binary_confidence': a.binary_confidence,
        'attack_confidence': a.attack_confidence,
        'src_ip':            a.src_ip,
        'dst_ip':            a.dst_ip,
        'src_port':          features.get('src_port', 0),
        'dst_port':          features.get('dst_port', 0),
        'protocol':          a.protocol,
        'src_bytes':         a.src_bytes,
        'dst_bytes':         a.dst_bytes,
        'duration':          a.duration,
        'detection_score':    a.detection_score,
        'final_score':        a.final_score,
        'asset_name':         a.asset_name,
        'asset_criticality':  a.asset_criticality,
        'asset_multiplier':   a.asset_multiplier,
        'features':          features,
        'status':            a.status,
        'action_taken':      a.action_taken,
        'source':            a.source,
        'detected_at':       a.detected_at.isoformat(),
        'organisation':      a.organisation.name if a.organisation else None,
    }


# ─── SETTINGS ─────────────────────────────────────────────────────────────────
class SettingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        s = IDSSettings.get(get_org(request))
        return Response({
            'binary_threshold':    s.binary_threshold,
            'confidence_alert':    s.confidence_alert,
            'thresholds': {
                'DoS':         s.threshold_dos,
                'DDoS':        s.threshold_ddos,
                'Probe':       s.threshold_probe,
                'R2L':         s.threshold_r2l,
                'U2R':         s.threshold_u2r,
                'BruteForce':  s.threshold_bruteforce,
                'WebAttack':   s.threshold_webattack,
                'Botnet':      s.threshold_botnet,
                'Infiltration':s.threshold_infiltration,
            },
            'auto_block_enabled':    s.auto_block_enabled,
            'auto_block_threshold':  s.auto_block_threshold,
            'auto_block_duration':   s.auto_block_duration,
            'river_enabled':         s.river_enabled,
            'river_learn_threshold': s.river_learn_threshold,
            'notif_enabled':         s.notif_enabled,
            'notif_telegram_token':  s.notif_telegram_token,
            'notif_telegram_chat':   s.notif_telegram_chat,
            'notif_email':           s.notif_email,
            'notif_webhook_url':     s.notif_webhook_url,
            'notif_min_severity':    s.notif_min_severity,
            'updated_at':            s.updated_at,
            'updated_by':            s.updated_by,
            'network_name':          s.network_name,
            'network_latitude':      s.network_latitude,
            'network_longitude':     s.network_longitude,

            'notif_telegram_enabled':    s.notif_telegram_enabled,
            'notif_email_enabled':       s.notif_email_enabled,
            'notif_email_address':       s.notif_email_address,
            'notif_email_min_severity':  s.notif_email_min_severity,
        })

    def put(self, request):
        s = IDSSettings.get(get_org(request))
        d = request.data

        if 'binary_threshold' in d: s.binary_threshold = float(d['binary_threshold'])
        if 'confidence_alert' in d: s.confidence_alert = float(d['confidence_alert'])

        thresholds = d.get('thresholds', {})
        if 'DoS'          in thresholds: s.threshold_dos          = float(thresholds['DoS'])
        if 'DDoS'         in thresholds: s.threshold_ddos         = float(thresholds['DDoS'])
        if 'Probe'        in thresholds: s.threshold_probe        = float(thresholds['Probe'])
        if 'R2L'          in thresholds: s.threshold_r2l          = float(thresholds['R2L'])
        if 'U2R'          in thresholds: s.threshold_u2r          = float(thresholds['U2R'])
        if 'BruteForce'   in thresholds: s.threshold_bruteforce   = float(thresholds['BruteForce'])
        if 'WebAttack'    in thresholds: s.threshold_webattack    = float(thresholds['WebAttack'])
        if 'Botnet'       in thresholds: s.threshold_botnet       = float(thresholds['Botnet'])
        if 'Infiltration' in thresholds: s.threshold_infiltration = float(thresholds['Infiltration'])

        if 'auto_block_enabled'   in d: s.auto_block_enabled   = bool(d['auto_block_enabled'])
        if 'auto_block_threshold' in d: s.auto_block_threshold = float(d['auto_block_threshold'])
        if 'auto_block_duration'  in d: s.auto_block_duration  = int(d['auto_block_duration'])

        if 'river_enabled'         in d: s.river_enabled         = bool(d['river_enabled'])
        if 'river_learn_threshold' in d: s.river_learn_threshold = float(d['river_learn_threshold'])

        if 'notif_enabled'        in d: s.notif_enabled        = bool(d['notif_enabled'])
        if 'notif_telegram_token' in d: s.notif_telegram_token = d['notif_telegram_token']
        if 'notif_telegram_chat'  in d: s.notif_telegram_chat  = d['notif_telegram_chat']
        if 'notif_email'          in d: s.notif_email          = d['notif_email']
        if 'notif_webhook_url'    in d: s.notif_webhook_url    = d['notif_webhook_url']
        if 'notif_min_severity'   in d: s.notif_min_severity   = d['notif_min_severity']

        if 'network_name'      in d: s.network_name      = d['network_name']
        if 'network_latitude'  in d: s.network_latitude  = float(d['network_latitude'])
        if 'network_longitude' in d: s.network_longitude = float(d['network_longitude'])

        if 'notif_telegram_enabled'   in d: s.notif_telegram_enabled   = bool(d['notif_telegram_enabled'])
        if 'notif_email_enabled'      in d: s.notif_email_enabled      = bool(d['notif_email_enabled'])
        if 'notif_email_address'      in d: s.notif_email_address      = d['notif_email_address']
        if 'notif_email_min_severity' in d: s.notif_email_min_severity = d['notif_email_min_severity']

        s.updated_by = request.user.username
        s.save()
        return Response({'status': 'ok', 'message': 'Paramètres sauvegardés'})


class WazuhStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        client = WazuhClient()
        wazuh_status = client.status()
        if not wazuh_status.get('success'):
            return Response(wazuh_status, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(wazuh_status)


# ─── TIMELINE ─────────────────────────────────────────────────────────────────
class TimelineView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.utils import timezone
        from datetime import timedelta
        from django.db.models.functions import TruncHour

        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)

        data = (
            tenant_qs(Alert, request)
            .filter(is_attack=True, detected_at__gte=since)
            .annotate(hour=TruncHour('detected_at'))
            .values('hour', 'attack_type')
            .annotate(count=Count('id'))
            .order_by('hour')
        )

        from collections import defaultdict
        timeline     = defaultdict(lambda: defaultdict(int))
        attack_types = set()

        for item in data:
            hour_str = item['hour'].strftime('%H:%M')
            timeline[hour_str][item['attack_type']] += item['count']
            attack_types.add(item['attack_type'])

        result = []
        now = timezone.now()
        for i in range(hours, -1, -1):
            h     = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
            h_str = h.strftime('%H:%M')
            entry = {'hour': h_str, 'total': 0}
            for t in attack_types:
                entry[t]       = timeline[h_str].get(t, 0)
                entry['total'] += entry[t]
            result.append(entry)

        return Response({
            'timeline':     result,
            'attack_types': list(attack_types),
            'hours':        hours,
        })


# ─── ANALYSE COMPORTEMENTALE ──────────────────────────────────────────────────

def update_ip_baseline(org, flow_data: dict, is_attack: bool) -> dict:
    from .models import IPBaseline
    src_ip = flow_data.get('src_ip', '')
    if not src_ip or not org:
        return {}

    is_internal = (
        src_ip.startswith('192.168.') or
        src_ip.startswith('10.')      or
        src_ip.startswith('172.16.')  or
        src_ip.startswith('172.17.')  or
        src_ip.startswith('172.18.')  or
        src_ip.startswith('172.31.')
    )

    baseline, _ = IPBaseline.objects.get_or_create(
        organisation=org,
        ip_address=src_ip,
        defaults={'is_internal': is_internal}
    )

    if is_attack:
        baseline.attack_count += 1

    result = baseline.update_baseline(flow_data)
    baseline.save()

    if result.get('anomalies') and not result.get('learning'):
        if result['anomaly_score'] >= 3.0:
            _create_behavioral_alert(org, src_ip, result, flow_data)

    return result


def _create_behavioral_alert(org, src_ip, behavioral_result, flow_data):
    score     = behavioral_result['anomaly_score']
    anomalies = behavioral_result['anomalies']
    asset = get_asset_for_ip(org, src_ip)
    criticality = asset.criticality if asset else 'INTERNAL'
    severity, final_score, multiplier = compute_cvss_severity(min(score, 10), criticality)

    from django.utils import timezone
    from datetime import timedelta
    recent = Alert.objects.filter(
        organisation     = org,
        src_ip           = src_ip,
        attack_type      = 'Behavioral',
        detected_at__gte = timezone.now() - timedelta(minutes=5),
    ).exists()
    if recent:
        return

    main_anomaly = anomalies[0] if anomalies else {}
    Alert.objects.create(
        organisation      = org,
        attack_type       = 'Behavioral',
        severity          = severity,
        is_attack         = True,
        binary_confidence = min(score / 10, 0.99),
        attack_confidence = min(score / 10, 0.99),
        detection_score   = min(score, 10),
        final_score       = final_score,
        asset_multiplier  = multiplier,
        asset_name        = asset.name if asset else '',
        asset_criticality = criticality,
        src_ip            = src_ip,
        dst_ip            = flow_data.get('dst_ip', ''),
        protocol          = flow_data.get('protocol', 'TCP'),
        src_bytes         = int(flow_data.get('src_bytes', 0)),
        dst_bytes         = int(flow_data.get('dst_bytes', 0)),
        duration          = float(flow_data.get('duration', 0)),
        status            = 'new',
        features          = {
            **flow_data,
            'behavioral':     True,
            'anomaly_score':  score,
            'anomalies':      anomalies,
            'anomaly_type':   main_anomaly.get('type', ''),
            'anomaly_detail': main_anomaly.get('detail', ''),
        },
        source = flow_data.get('source', 'scapy'),
    )

    details = '\n'.join([f"  • {a['detail']}" for a in anomalies[:3]])
    send_telegram(
        f"🔍 <b>Anomalie comportementale</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>IP</b>    : <code>{src_ip}</code>\n"
        f"📊 <b>Score</b> : {score:.1f}/10\n"
        f"🏷️ <b>Criticité actif</b> : {criticality}\n"
        f"🔴 <b>Sévérité</b> : {severity}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{details}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 Mylo IPS Security Center",
        organisation=org,
    )


# ─── VUE BASELINES ────────────────────────────────────────────────────────────

class IPBaselineListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import IPBaseline
        suspicious_only = request.query_params.get('suspicious') == 'true'
        internal_only   = request.query_params.get('internal')   == 'true'
        limit           = int(request.query_params.get('limit', 50))

        qs = IPBaseline.objects.filter(organisation=get_org(request))
        if suspicious_only: qs = qs.filter(is_suspicious=True)
        if internal_only:   qs = qs.filter(is_internal=True)

        return Response([_serialize_baseline(b) for b in qs[:limit]])


class IPBaselineDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, ip):
        from .models import IPBaseline
        try:
            b = IPBaseline.objects.get(organisation=get_org(request), ip_address=ip)
            return Response(_serialize_baseline(b, detail=True))
        except IPBaseline.DoesNotExist:
            return Response({'error': 'IP non trouvée'}, status=404)

    def delete(self, request, ip):
        from .models import IPBaseline
        try:
            b = IPBaseline.objects.get(organisation=get_org(request), ip_address=ip)
            b.delete()
            return Response({'message': f'Baseline de {ip} réinitialisée'})
        except IPBaseline.DoesNotExist:
            return Response({'error': 'IP non trouvée'}, status=404)


class BehavioralStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import IPBaseline
        from django.db.models import Avg, Max

        org = get_org(request)
        qs  = IPBaseline.objects.filter(organisation=org)

        return Response({
            'total_ips':         qs.count(),
            'suspicious_ips':    qs.filter(is_suspicious=True).count(),
            'internal_ips':      qs.filter(is_internal=True).count(),
            'external_ips':      qs.filter(is_internal=False).count(),
            'baselines_ready':   qs.filter(baseline_established=True).count(),
            'avg_anomaly_score': round(qs.aggregate(Avg('anomaly_score'))['anomaly_score__avg'] or 0, 2),
            'max_anomaly_score': round(qs.aggregate(Max('anomaly_score'))['anomaly_score__max'] or 0, 2),
            'top_suspicious': list(
                qs.filter(is_suspicious=True)
                  .order_by('-anomaly_score')
                  .values('ip_address', 'anomaly_score', 'last_anomaly_type',
                          'attack_count', 'total_flows', 'last_seen')[:10]
            ),
        })


def _serialize_baseline(b, detail=False):
    data = {
        'ip_address':           b.ip_address,
        'is_internal':          b.is_internal,
        'is_suspicious':        b.is_suspicious,
        'anomaly_score':        round(b.anomaly_score, 2),
        'last_anomaly_type':    b.last_anomaly_type,
        'baseline_established': b.baseline_established,
        'total_flows':          b.total_flows,
        'attack_count':         b.attack_count,
        'first_seen':           b.first_seen.isoformat(),
        'last_seen':            b.last_seen.isoformat(),
    }
    if detail:
        data.update({
            'avg_bytes_per_flow':   round(b.avg_bytes_per_flow, 2),
            'avg_duration':         round(b.avg_duration, 4),
            'avg_requests_per_min': round(b.avg_requests_per_min, 2),
            'std_bytes_per_flow':   round(b.std_bytes_per_flow, 2),
            'typical_ports':        b.typical_ports,
            'typical_protocols':    b.typical_protocols,
            'typical_dst_ips':      b.typical_dst_ips,
            'total_bytes':          b.total_bytes,
        })
    return data


# ─── MOTEUR DE CORRÉLATION D'ALERTES ─────────────────────────────────────────

# Fenêtre de temps pour corréler les alertes (10 minutes)
CORRELATION_WINDOW_MINUTES = 10

# Scénarios connus — séquences d'attaques typiques
ATTACK_SCENARIOS = [
    {
        'type':       'recon_exploit',
        'sequence':   ['Probe', 'BruteForce'],
        'risk':       'CRITICAL',
        'desc':       "Reconnaissance suivie d'une tentative d'exploitation — pattern classique d'attaque ciblée",
        'next_step':  'U2R ou R2L probable',
        'action':     'Bloquer immédiatement cette IP et investiguer les logs d\'accès',
        'confidence': 0.90,
    },
    {
        'type':       'recon_dos',
        'sequence':   ['Probe', 'DoS'],
        'risk':       'CRITICAL',
        'desc':       "Reconnaissance puis attaque par déni de service — tentative de mise hors ligne après cartographie",
        'next_step':  'DDoS amplifié probable',
        'action':     'Bloquer l\'IP et alerter l\'équipe réseau',
        'confidence': 0.88,
    },
    {
        'type':       'recon_dos',
        'sequence':   ['Probe', 'DDoS'],
        'risk':       'CRITICAL',
        'desc':       "Reconnaissance puis DDoS — attaque coordonnée en cours",
        'next_step':  'Exploitation de services exposés',
        'action':     'Activation du mode défensif — bloquer le subnet source',
        'confidence': 0.92,
    },
    {
        'type':       'brute_exploit',
        'sequence':   ['BruteForce', 'R2L'],
        'risk':       'CRITICAL',
        'desc':       "BruteForce suivi d'accès non autorisé — compromission probable",
        'next_step':  'Élévation de privilèges (U2R)',
        'action':     'URGENCE — Réinitialiser les credentials et auditer les accès',
        'confidence': 0.95,
    },
    {
        'type':       'persistence',
        'sequence':   ['BruteForce', 'U2R'],
        'risk':       'CRITICAL',
        'desc':       "BruteForce puis élévation de privilèges — attaquant possiblement root",
        'next_step':  'Installation de backdoor ou exfiltration',
        'action':     'ISOLATION IMMÉDIATE de la machine cible',
        'confidence': 0.97,
    },
    {
        'type':       'lateral_movement',
        'sequence':   ['Probe', 'BruteForce', 'R2L'],
        'risk':       'CRITICAL',
        'desc':       "Séquence complète Recon→Force→Accès — mouvement latéral en cours",
        'next_step':  'Propagation vers d\'autres machines',
        'action':     'Bloquer l\'IP, isoler les machines ciblées, forensics immédiat',
        'confidence': 0.98,
    },
    {
        'type':       'multi_vector',
        'sequence':   ['DoS', 'BruteForce'],
        'risk':       'HIGH',
        'desc':       "Attaque DoS en couverture pendant une tentative de BruteForce — tactique de diversion",
        'next_step':  'Accès non autorisé pendant la perturbation',
        'action':     'Ne pas se concentrer uniquement sur le DoS — vérifier les accès',
        'confidence': 0.82,
    },
    {
        'type':       'coordinated',
        'sequence':   ['Probe', 'WebAttack'],
        'risk':       'HIGH',
        'desc':       "Scan de vulnérabilités web suivi d'une exploitation — attaque applicative",
        'next_step':  'Injection SQL ou XSS ciblé',
        'action':     'Vérifier les logs applicatifs et WAF',
        'confidence': 0.85,
    },
    {
        'type':       'data_exfiltration',
        'sequence':   ['Infiltration', 'Botnet'],
        'risk':       'CRITICAL',
        'desc':       "Infiltration suivie d'activité botnet — machine possiblement compromise et contrôlée",
        'next_step':  'Exfiltration de données sensibles',
        'action':     'Isoler la machine du réseau, analyse forensique',
        'confidence': 0.93,
    },
]


def correlate_alerts(org, new_alert) -> dict:
    """
    Analyse les alertes récentes pour détecter des scénarios d'attaque.
    Appelé après chaque nouvelle alerte is_attack=True.
    Retourne la corrélation créée/mise à jour si trouvée.
    """
    from .models import Alert, AlertCorrelation
    from django.utils import timezone
    from datetime import timedelta

    if not new_alert.is_attack or not new_alert.src_ip:
        return {}

    src_ip = new_alert.src_ip
    since  = timezone.now() - timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    # Récupérer toutes les alertes récentes pour cette IP
    recent_alerts = list(
        Alert.objects.filter(
            organisation = org,
            src_ip       = src_ip,
            is_attack    = True,
            detected_at__gte = since,
        ).order_by('detected_at').values('id', 'attack_type', 'detected_at', 'severity')
    )

    if len(recent_alerts) < 2:
        return {}

    # Extraire la séquence de types d'attaques
    attack_sequence = [a['attack_type'] for a in recent_alerts]

    # Chercher un scénario connu
    matched_scenario = None
    for scenario in ATTACK_SCENARIOS:
        seq = scenario['sequence']
        # Vérifier si la séquence du scénario est contenue dans les alertes récentes
        if _sequence_matches(attack_sequence, seq):
            matched_scenario = scenario
            break

    # Si pas de scénario connu mais >= 3 attaques différentes → multi-vecteurs
    if not matched_scenario:
        unique_types = list(dict.fromkeys(attack_sequence))  # dédupliqué ordonné
        if len(unique_types) >= 3:
            matched_scenario = {
                'type':       'multi_vector',
                'sequence':   unique_types[:5],
                'risk':       'HIGH',
                'desc':       f"Attaque multi-vecteurs : {' → '.join(unique_types[:5])} depuis la même source",
                'next_step':  'Escalade probable',
                'action':     'Surveiller et envisager le blocage de cette IP',
                'confidence': 0.75,
            }
        elif len(recent_alerts) >= 4:
            # Même type répété plusieurs fois → attaque persistante
            matched_scenario = {
                'type':       'coordinated',
                'sequence':   unique_types,
                'risk':       'MEDIUM',
                'desc':       f"Attaques répétées ({len(recent_alerts)}x {attack_sequence[-1]}) depuis {src_ip}",
                'next_step':  'Escalade de l\'intensité',
                'action':     'Envisager le blocage de cette IP',
                'confidence': 0.70,
            }

    if not matched_scenario:
        return {}

    # Créer ou mettre à jour la corrélation
    correlation, created = AlertCorrelation.objects.get_or_create(
        organisation = org,
        src_ip       = src_ip,
        is_active    = True,
        defaults={
            'scenario_type':        matched_scenario['type'],
            'risk_level':           matched_scenario['risk'],
            'description':          matched_scenario['desc'],
            'next_step_prediction': matched_scenario.get('next_step', ''),
            'confidence':           matched_scenario['confidence'],
            'recommended_action':   matched_scenario.get('action', ''),
            'attack_types':         attack_sequence,
            'alert_count':          len(recent_alerts),
            'first_alert_at':       recent_alerts[0]['detected_at'],
        }
    )

    if not created:
        # Mettre à jour la corrélation existante
        correlation.attack_types  = attack_sequence
        correlation.alert_count   = len(recent_alerts)
        correlation.risk_level    = matched_scenario['risk']
        correlation.description   = matched_scenario['desc']
        correlation.next_step_prediction = matched_scenario.get('next_step', '')
        correlation.recommended_action   = matched_scenario.get('action', '')
        correlation.scenario_type = matched_scenario['type']
        correlation.save()

    # Lier les alertes à la corrélation
    alert_ids = [a['id'] for a in recent_alerts]
    alerts_qs = Alert.objects.filter(id__in=alert_ids)
    correlation.alerts.set(alerts_qs)

    # Notification Telegram (une seule fois par corrélation)
    if not correlation.is_notified:
        _notify_correlation(org, correlation, attack_sequence)
        correlation.is_notified = True
        correlation.save()

    return {
        'correlation_id':   correlation.id,
        'scenario':         matched_scenario['type'],
        'risk':             matched_scenario['risk'],
        'description':      matched_scenario['desc'],
        'next_step':        matched_scenario.get('next_step', ''),
        'action':           matched_scenario.get('action', ''),
        'alert_count':      len(recent_alerts),
        'sequence':         attack_sequence,
        'confidence':       matched_scenario['confidence'],
    }


def _sequence_matches(alert_types: list, scenario_seq: list) -> bool:
    """Vérifie si la séquence du scénario apparaît dans les alertes (dans l'ordre)."""
    if len(scenario_seq) > len(alert_types):
        return False
    # Chercher la sous-séquence ordonnée
    seq_idx = 0
    for atype in alert_types:
        if seq_idx < len(scenario_seq) and atype == scenario_seq[seq_idx]:
            seq_idx += 1
        if seq_idx == len(scenario_seq):
            return True
    return False


def _notify_correlation(org, correlation, sequence):
    """Envoie une notification Telegram pour une corrélation détectée."""
    risk_emoji = {
        'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'
    }
    emoji = risk_emoji.get(correlation.risk_level, '⚠️')

    send_telegram(
        f"{emoji} <b>SCÉNARIO D'ATTAQUE DÉTECTÉ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>IP Source</b>  : <code>{correlation.src_ip}</code>\n"
        f"⚡ <b>Scénario</b>   : {correlation.get_scenario_type_display()}\n"
        f"🔴 <b>Risque</b>     : {correlation.risk_level}\n"
        f"📊 <b>Séquence</b>   : {' → '.join(sequence[-5:])}\n"
        f"🔮 <b>Prochaine étape</b> : {correlation.next_step_prediction}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💡 <b>Action</b> : {correlation.recommended_action}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 Mylo IPS Security Center",
        organisation=org,
    )


# ─── VUES CORRÉLATION ─────────────────────────────────────────────────────────

class CorrelationListView(APIView):
    """GET /api/alerts/correlations/"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import AlertCorrelation
        active_only = request.query_params.get('active') != 'false'
        limit       = int(request.query_params.get('limit', 50))

        qs = AlertCorrelation.objects.filter(organisation=get_org(request))
        if active_only:
            qs = qs.filter(is_active=True)

        return Response([_serialize_correlation(c) for c in qs[:limit]])


class CorrelationDetailView(APIView):
    """GET/PATCH /api/alerts/correlations/<id>/"""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        from .models import AlertCorrelation
        try:
            c = AlertCorrelation.objects.get(pk=pk, organisation=get_org(request))
            return Response(_serialize_correlation(c, detail=True))
        except AlertCorrelation.DoesNotExist:
            return Response({'error': 'Corrélation introuvable'}, status=404)

    def patch(self, request, pk):
        from .models import AlertCorrelation
        from django.utils import timezone
        try:
            c = AlertCorrelation.objects.get(pk=pk, organisation=get_org(request))
        except AlertCorrelation.DoesNotExist:
            return Response({'error': 'Corrélation introuvable'}, status=404)

        if request.data.get('resolve'):
            c.is_active   = False
            c.resolved_at = timezone.now()
            c.save()
            return Response({'message': 'Corrélation résolue'})

        return Response({'error': 'Action inconnue'}, status=400)


class CorrelationStatsView(APIView):
    """GET /api/alerts/correlations/stats/"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import AlertCorrelation
        from django.db.models import Count

        org = get_org(request)
        qs  = AlertCorrelation.objects.filter(organisation=org)

        return Response({
            'total':          qs.count(),
            'active':         qs.filter(is_active=True).count(),
            'critical':       qs.filter(risk_level='CRITICAL', is_active=True).count(),
            'by_scenario':    dict(qs.values_list('scenario_type').annotate(c=Count('id')).values_list('scenario_type', 'c')),
            'by_risk':        dict(qs.values_list('risk_level').annotate(c=Count('id')).values_list('risk_level', 'c')),
            'top_ips': list(
                qs.filter(is_active=True)
                  .values('src_ip')
                  .annotate(count=Count('id'))
                  .order_by('-count')[:10]
            ),
        })


def _serialize_correlation(c, detail=False):
    data = {
        'id':                   c.id,
        'src_ip':               c.src_ip,
        'scenario_type':        c.scenario_type,
        'scenario_label':       c.get_scenario_type_display(),
        'risk_level':           c.risk_level,
        'description':          c.description,
        'next_step_prediction': c.next_step_prediction,
        'recommended_action':   c.recommended_action,
        'confidence':           round(c.confidence, 2),
        'attack_types':         c.attack_types,
        'alert_count':          c.alert_count,
        'is_active':            c.is_active,
        'first_alert_at':       c.first_alert_at.isoformat(),
        'last_alert_at':        c.last_alert_at.isoformat(),
        'duration_seconds':     c.duration_seconds(),
    }
    if detail:
        data['alerts'] = [
            {
                'id':          a.id,
                'attack_type': a.attack_type,
                'severity':    a.severity,
                'detected_at': a.detected_at.isoformat(),
            }
            for a in c.alerts.order_by('detected_at')[:20]
        ]
    return data


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def mobile_dashboard(request):
    """
    Endpoint dédié app mobile — agrège KPIs + activité 7 jours + alertes récentes.
    Un seul appel pour tout le dashboard.
    """
    from alerts.models import Alert, AlertCorrelation, BlacklistedIP  # ← ajouter cette ligne
    from django.utils import timezone
    from datetime import timedelta
    from django.db.models import Count

    org = request.user.organisation
    today = timezone.now().date()

    qs = Alert.objects.filter(organisation=org)
    qs_all = Alert.objects.filter(organisation=org)

    # ── KPIs ────────────────────────────────────────────────────
    total_today    = qs.filter(detected_at__date=today).count()
    incidents      = AlertCorrelation.objects.filter(
        organisation=org, is_active=True
    ).count()
    blocked        = BlacklistedIP.objects.filter(
        organisation=org, is_active=True
    ).count()

    # Alertes à vérifier (basse confiance)
    low_conf = qs.filter(
        detected_at__date=today,
        attack_confidence__lt=0.70
    ).count()

    # ── Activité 7 jours ────────────────────────────────────────
    daily = []
    for i in range(29, -1, -1):   # 30 jours
        day = today - timedelta(days=i)
        count = qs.filter(detected_at__date=day).count()
        daily.append({
            "date":  str(day),
            "label": ["L", "M", "M", "J", "V", "S", "D"][day.weekday()],
            "count": count,
        })

    max_count = max((d["count"] for d in daily), default=1) or 1
    for d in daily:
        d["ratio"] = round(d["count"] / max_count, 2)

    # ── Alertes récentes ─────────────────────────────────────────
    recent = list(
        qs.order_by("-detected_at")[:10].values(
            "id", "attack_type", "severity",
            "src_ip", "dst_ip", "protocol",
            "attack_confidence", "status", "detected_at"
        )
    )
    for r in recent:
        r["detected_at"] = r["detected_at"].isoformat()

    # ── Répartition par type (top 5) ────────────────────────────
    thirty_days_ago = today - timedelta(days=30)
    by_type = list(
        qs.filter(detected_at__date__gte=thirty_days_ago)
        .values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )

    return Response({
        "kpis": {
            "alerts_today":    total_today,
            "incidents_active": incidents,
            "blocked_ips":     blocked,
            "low_confidence":  low_conf,
            "model_accuracy":  90.29,
        },
        "daily_activity": daily,
        "recent_alerts":  recent,
        "top_attack_types": by_type,
    })



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def baseline_phase(request):
    """Retourne la phase baseline actuelle pour capture.py"""
    org = request.user.organisation
    if not org:
        return Response({'phase': 'production', 'message': 'Pas d\'organisation'})

    manager = BaselineManager(org)
    phase, message, progression = manager.get_phase()

    settings = manager._get_settings()

    return Response({
        'phase':            phase,
        'message':          message,
        'progression':      progression,
        'river_threshold':  getattr(settings, 'river_learn_threshold', 0.70),
        'stats':            manager.get_stats(),
    })


class CopilotAgentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        message = request.data.get('message', '').strip()
        history = request.data.get('history', [])
        if not message:
            return Response({'error': 'Message vide'}, status=400)
        org = get_org(request)
        from .copilot_agent import run_agent
        try:
            reply = run_agent(message, org, history)
            return Response({'reply': reply})
        except Exception as e:
            return Response({'error': str(e)}, status=500)
