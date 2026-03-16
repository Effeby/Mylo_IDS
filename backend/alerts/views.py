from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.db.models import Count
import requests
import random
from django.conf import settings
from .models import Alert, BlacklistedIP, WhitelistedIP, IDSSettings

# ─── TELEGRAM ────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = '8649586999:AAGJ1TtxfnRQ02doY4SYV00TmYfvw1JnAx4'
TELEGRAM_CHAT_ID = '5225530595'

def send_telegram(message: str):
    """Envoie une notification Telegram en arrière-plan — non bloquant."""
    import threading
    def _send():
        try:
            requests.post(
                f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
                json={
                    'chat_id':    TELEGRAM_CHAT_ID,
                    'text':       message,
                    'parse_mode': 'HTML',
                },
                timeout=5
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
    """Envoie le feedback à River directement (sans HTTP) — non bloquant."""
    import threading
    def _learn():
        try:
            # Import direct pour éviter le problème d'auth JWT
            from actions.views import _get_model, _river_state, _save_river, XGB_FEATURES, ALL_CLASSES
            from river import metrics as river_metrics

            if true_label not in ALL_CLASSES:
                return

            model = _get_model()
            x = {k: float(features.get(k, 0)) for k in XGB_FEATURES}

            # Prédire avant d'apprendre
            y_pred = model.predict_one(x)
            if y_pred is not None:
                _river_state['metric'].update(true_label, y_pred)
                # report peut ne pas exister si state chargé depuis ancien pkl
                if 'report' in _river_state:
                    _river_state['report'].update(true_label, y_pred)

            # Apprendre
            model.learn_one(x, true_label)
            _river_state['total'] += 1
            _river_state['counts'][true_label] = _river_state['counts'].get(true_label, 0) + 1

            # Historique
            from django.utils import timezone
            _river_state['history'].append({
                'total':    _river_state['total'],
                'accuracy': round(_river_state['metric'].get(), 4),
                'label':    true_label,
                'correct':  y_pred == true_label,
                'time':     timezone.now().isoformat(),
            })

            # Sauvegarder
            _save_river()

            # Persister en BDD tous les 5
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

            # Recharger River dans FastAPI
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
        status_filter = request.query_params.get('status')
        date_from     = request.query_params.get('date_from')  # YYYY-MM-DD
        date_to       = request.query_params.get('date_to')    # YYYY-MM-DD

        qs = Alert.objects.all()
        if attack_type:   qs = qs.filter(attack_type=attack_type)
        if severity:      qs = qs.filter(severity=severity)
        if src_ip:        qs = qs.filter(src_ip__icontains=src_ip)
        if status_filter: qs = qs.filter(status=status_filter)
        if date_from:     qs = qs.filter(detected_at__date__gte=date_from)
        if date_to:       qs = qs.filter(detected_at__date__lte=date_to)

        alerts = qs[:limit]
        return Response([_serialize_alert(a) for a in alerts])


# ─── DÉTAIL D'UNE ALERTE ──────────────────────────────────────────────────────
class AlertDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            a = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Alerte introuvable'}, status=404)
        return Response(_serialize_alert(a))

    def patch(self, request, pk):
        try:
            a = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Alerte introuvable'}, status=404)

        new_status = request.data.get('status')
        if not new_status:
            return Response({'error': 'Champ status manquant'}, status=400)

        a.status = new_status
        a.save()

        river_triggered = False

        # ── Faux positif → River apprend "Normal" ─────────────────────
        if new_status == 'false_positive' and a.features:
            trigger_river_learning(a.features, 'Normal')
            river_triggered = True
            # Whitelister l'IP si confiance faible — champs corrects du modèle
            if a.src_ip and a.binary_confidence < 0.85:
                WhitelistedIP.objects.get_or_create(
                    ip_address=a.src_ip,
                    defaults={
                        'description': f'Faux positif — {a.attack_type} ({a.binary_confidence:.2f})',
                    }
                )

        # ── Attaque confirmée → River apprend le vrai type ────────────
        elif new_status == 'confirmed' and a.features:
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
        total      = Alert.objects.count()
        attacks    = Alert.objects.filter(is_attack=True).count()
        by_type    = dict(
            Alert.objects.filter(is_attack=True)
            .values_list('attack_type')
            .annotate(c=Count('id'))
            .values_list('attack_type', 'c')
        )
        by_severity = dict(
            Alert.objects.filter(is_attack=True)
            .values_list('severity')
            .annotate(c=Count('id'))
            .values_list('severity', 'c')
        )
        false_positives = Alert.objects.filter(status='false_positive').count()
        under_review    = Alert.objects.filter(status='under_review').count()
        ignored         = Alert.objects.filter(status='ignored').count()
        new_alerts      = Alert.objects.filter(status='new', is_attack=True).count()
        top_ips = list(
            Alert.objects.filter(is_attack=True)
            .values('src_ip')
            .annotate(count=Count('id'))
            .order_by('-count')[:5]
        )

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

        src_ip = traffic_data.get('src_ip') or random.choice(SIMULATED_SRC_IPS)
        dst_ip = traffic_data.get('dst_ip') or random.choice(SIMULATED_DST_IPS)

        if WhitelistedIP.objects.filter(ip_address=src_ip).exists():
            return Response({
                'is_attack':         False,
                'binary_label':      'Normal',
                'binary_confidence': 0.0,
                'attack_type':       'Normal',
                'attack_confidence': 1.0,
                'severity':          'LOW',
                'alert_status':      'Ignorée',
                'src_ip':            src_ip,
                'dst_ip':            dst_ip,
                'whitelisted':       True,
            })

        try:
            payload = {**traffic_data, 'src_ip': src_ip, 'dst_ip': dst_ip}
            resp = requests.post(
                f"{settings.MYLO_FASTAPI_URL}/predict",
                json=payload,
                timeout=5
            )
            prediction = resp.json()
        except Exception as e:
            return Response({'error': f'FastAPI indisponible: {e}'}, status=503)

        severity     = SEVERITY_MAP.get(prediction.get('attack_type', 'Normal'), 'LOW')
        alert_status = prediction.get('alert_status', 'Nouvelle')

        STATUS_MAP = {
            'Nouvelle':    'new',
            'À vérifier':  'under_review',
            'Ignorée':     'ignored',
            'Normal':      'normal',
        }
        db_status = STATUS_MAP.get(alert_status, 'new')

        alert = Alert.objects.create(
            attack_type       = prediction.get('attack_type', 'Normal'),
            severity          = severity,
            binary_confidence = prediction.get('binary_confidence', 0),
            attack_confidence = prediction.get('attack_confidence', 0),
            is_attack         = prediction.get('is_attack', False),
            src_ip            = src_ip,
            dst_ip            = dst_ip,
            protocol          = traffic_data.get('protocol', random.choice(PROTOCOLS)),
            src_bytes         = traffic_data.get('src_bytes', 0),
            dst_bytes         = traffic_data.get('dst_bytes', 0),
            duration          = traffic_data.get('duration', 0),
            status            = db_status,
            features          = {
                **{k: v for k, v in traffic_data.items()
                   if k not in ('src_ip', 'dst_ip')},
                # Stocker les ports dans les features pour affichage
                'src_port': traffic_data.get('src_port', 0),
                'dst_port': traffic_data.get('dst_port', 0),
            },
        )

        # ── Notification Telegram si attaque HIGH/CRITICAL ──────────
        if prediction.get('is_attack') and severity in ('HIGH', 'CRITICAL', 'MEDIUM'):
            send_telegram(
                f"🚨 <b>MYLO IDS — SecureBank</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"⚠️ <b>Type</b>     : {prediction.get('attack_type')}\n"
                f"🔴 <b>Sévérité</b> : {severity}\n"
                f"🌐 <b>IP Source</b> : <code>{src_ip}</code>\n"
                f"🎯 <b>IP Dest</b>   : <code>{dst_ip}</code>\n"
                f"📊 <b>Confiance</b> : {prediction.get('binary_confidence', 0)*100:.1f}%\n"
                f"🕐 <b>Heure</b>     : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🏦 SecureBank Security Center"
            )

        action = None
        if (settings.MYLO_AUTO_BLOCK
                and prediction.get('is_attack')
                and prediction.get('binary_confidence', 0) >= settings.MYLO_BLOCK_THRESHOLD
                and alert_status == 'Nouvelle'):
            BlacklistedIP.objects.get_or_create(
                ip_address=src_ip,
                defaults={
                    'reason':     f"Auto — {prediction.get('attack_type')} ({prediction.get('binary_confidence'):.2f})",
                    'blocked_by': 'auto',
                }
            )
            alert.action_taken = 'auto_blocked'
            alert.save()
            action = 'blocked'

        return Response({
            **prediction,
            'alert_id':     alert.id,
            'src_ip':       src_ip,
            'dst_ip':       dst_ip,
            'severity':     severity,
            'alert_status': alert_status,
            'action':       action,
        })


# ─── BLACKLIST ────────────────────────────────────────────────────────────────
class BlacklistView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ips = BlacklistedIP.objects.filter(is_active=True)
        return Response([{
            'id':          ip.id,
            'ip_address':  ip.ip_address,
            'reason':      ip.reason,
            'blocked_by':  ip.blocked_by,
            'alert_count': ip.alert_count,
            'created_at':  ip.created_at.isoformat(),
        } for ip in ips])

    def post(self, request):
        ip     = request.data.get('ip_address')
        reason = request.data.get('reason', 'Bloqué manuellement')
        obj, created = BlacklistedIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': reason, 'blocked_by': 'manual'}
        )
        if not created:
            obj.is_active = True
            obj.save()
        return Response({'message': f'{ip} blacklistée', 'created': created})

    def delete(self, request):
        ip = request.data.get('ip_address')
        BlacklistedIP.objects.filter(ip_address=ip).update(is_active=False)
        return Response({'message': f'{ip} débloquée'})


# ─── HELPER ───────────────────────────────────────────────────────────────────
def _serialize_alert(a):
    features = a.features or {}
    return {
        'id':                a.id,
        'attack_type':       a.attack_type,
        'severity':          a.severity,
        'is_attack':         bool(a.is_attack),   # ← manquait !
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
        'features':          features,
        'status':            a.status,
        'action_taken':      a.action_taken,
        'detected_at':       a.detected_at.isoformat(),
    }


# ─── SETTINGS ─────────────────────────────────────────────────────────────────
class SettingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        s = IDSSettings.get()
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
        })

    def put(self, request):
        s = IDSSettings.get()
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

        s.updated_by = request.user.username
        s.save()

        return Response({'status': 'ok', 'message': 'Paramètres sauvegardés'})


class TimelineView(APIView):
    """GET /api/alerts/timeline/ — attaques groupées par heure sur 24h."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.utils import timezone
        from datetime import timedelta
        from django.db.models.functions import TruncHour

        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)

        # Grouper les attaques par heure
        data = (
            Alert.objects
            .filter(is_attack=True, detected_at__gte=since)
            .annotate(hour=TruncHour('detected_at'))
            .values('hour', 'attack_type')
            .annotate(count=Count('id'))
            .order_by('hour')
        )

        # Construire timeline heure par heure
        from collections import defaultdict
        timeline = defaultdict(lambda: defaultdict(int))
        attack_types = set()

        for item in data:
            hour_str = item['hour'].strftime('%H:%M')
            timeline[hour_str][item['attack_type']] += item['count']
            attack_types.add(item['attack_type'])

        # Remplir toutes les heures (même vides)
        result = []
        now = timezone.now()
        for i in range(hours, -1, -1):
            h = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
            h_str = h.strftime('%H:%M')
            entry = {'hour': h_str, 'total': 0}
            for t in attack_types:
                entry[t] = timeline[h_str].get(t, 0)
                entry['total'] += entry[t]
            result.append(entry)

        return Response({
            'timeline':     result,
            'attack_types': list(attack_types),
            'hours':        hours,
        })