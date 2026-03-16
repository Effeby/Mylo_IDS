# Test attaque Mylo IDS — declenche une notification Telegram
# Lance : python test_attack.py
import requests
import json

DJANGO_URL     = 'http://localhost:8001'
TELEGRAM_TOKEN = '8649586999:AAGJ1TtxfnRQ02doY4SYV00TmYfvw1JnAx4'
TELEGRAM_CHAT  = '5225530595'

# ── Auth Django ───────────────────────────────────────────────────────
print("Connexion Django...")
r = requests.post(f'{DJANGO_URL}/api/auth/login/', json={
    'username': 'admin', 'password': 'mylo2025'
})
token = r.json().get('access')
if not token:
    print("Erreur auth — verifie Django")
    exit()
print("Auth OK")
headers = {'Authorization': f'Bearer {token}'}

# ── Test Telegram direct ──────────────────────────────────────────────
print("\nTest Telegram...")
try:
    tg = requests.post(
        f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
        json={
            'chat_id':    TELEGRAM_CHAT,
            'text':       '🧪 <b>MYLO IDS — Test de connexion</b>\nTelegram opérationnel ✅',
            'parse_mode': 'HTML',
        },
        timeout=10
    )
    tg_res = tg.json()
    if tg_res.get('ok'):
        print("Telegram OK — message envoyé")
    else:
        print(f"Telegram ERREUR : {tg_res.get('description')}")
except Exception as e:
    print(f"Telegram ERREUR connexion : {e}")

# ── Patterns d'attaques ───────────────────────────────────────────────
ATTACKS = [
    {
        'name': 'Neptune (DoS) — pattern NSL-KDD exact',
        'payload': {
            'src_bytes': 0, 'dst_bytes': 0,
            'count': 511, 'srv_count': 511,
            'serror_rate': 1.0, 'srv_serror_rate': 1.0,
            'rerror_rate': 0.0, 'diff_srv_rate': 0.0,
            'same_srv_rate': 1.0,
            'dst_host_count': 255, 'dst_host_srv_count': 255,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 1.0,
            'dst_host_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0,
            'protocol_type': 2, 'flag': 0,
            'logged_in': 0, 'duration': 0,
            'bytes_ratio': 0, 'bytes_per_packet': 0, 'serror_diff': 1.0,
            'src_ip': '185.220.101.99', 'dst_ip': '10.0.0.1',
            'src_port': 54321, 'dst_port': 80, 'protocol': 'TCP',
        }
    },
    {
        'name': 'Smurf (DDoS) — ICMP flood',
        'payload': {
            'src_bytes': 1032, 'dst_bytes': 0,
            'count': 511, 'srv_count': 511,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'diff_srv_rate': 0.0,
            'same_srv_rate': 1.0,
            'dst_host_count': 255, 'dst_host_srv_count': 255,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 1.0,
            'dst_host_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'protocol_type': 0, 'flag': 10,
            'logged_in': 0, 'duration': 0,
            'bytes_ratio': 1032, 'bytes_per_packet': 1032, 'serror_diff': 0.0,
            'src_ip': '203.0.113.42', 'dst_ip': '192.168.1.255',
            'protocol': 'ICMP',
        }
    },
    {
        'name': 'PortScan (Probe) — nmap style',
        'payload': {
            'src_bytes': 0, 'dst_bytes': 0,
            'count': 1, 'srv_count': 1,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 1.0, 'diff_srv_rate': 1.0,
            'same_srv_rate': 0.0,
            'dst_host_count': 255, 'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 1.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_serror_rate': 0.0, 'dst_host_rerror_rate': 1.0,
            'protocol_type': 2, 'flag': 8,
            'logged_in': 0, 'duration': 0,
            'bytes_ratio': 0, 'bytes_per_packet': 0, 'serror_diff': -1.0,
            'src_ip': '198.51.100.7', 'dst_ip': '10.0.0.2',
            'src_port': 12345, 'dst_port': 22, 'protocol': 'TCP',
        }
    },
    {
        'name': 'BruteForce SSH',
        'payload': {
            'src_bytes': 2048, 'dst_bytes': 512,
            'count': 100, 'srv_count': 100,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.8, 'diff_srv_rate': 0.0,
            'same_srv_rate': 1.0,
            'dst_host_count': 100, 'dst_host_srv_count': 100,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.9,
            'dst_host_serror_rate': 0.0, 'dst_host_rerror_rate': 0.8,
            'protocol_type': 2, 'flag': 10,
            'logged_in': 0, 'duration': 1,
            'bytes_ratio': 4.0, 'bytes_per_packet': 20.48, 'serror_diff': -0.8,
            'src_ip': '172.16.0.50', 'dst_ip': '10.0.0.1',
            'src_port': 45678, 'dst_port': 22, 'protocol': 'TCP',
        }
    },
]

print("\n" + "="*60)
print("  MYLO IDS — Test Attaques + Notification Telegram")
print("="*60)

for attack in ATTACKS:
    print(f"\nTest : {attack['name']}")
    r = requests.post(
        f'{DJANGO_URL}/api/alerts/analyze/',
        json=attack['payload'],
        headers=headers
    )
    try:
        res = r.json()
    except Exception:
        print(f'  Erreur Django (status {r.status_code}): {r.text[:300]}')
        continue

    attack_type = res.get('attack_type', '?')
    is_attack   = res.get('is_attack', False)
    confidence  = res.get('binary_confidence', 0) * 100
    severity    = res.get('severity', '?')
    alert_id    = res.get('alert_id', '?')

    print(f"  Classe    : {attack_type}")
    print(f"  Severite  : {severity}")
    print(f"  Confiance : {confidence:.1f}%")
    print(f"  Alerte ID : #{alert_id}")

    # Vérifier si Telegram a bien reçu la notif
    if is_attack and severity in ('HIGH', 'CRITICAL'):
        print(f"  Verification Telegram...")
        try:
            tg = requests.post(
                f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
                json={
                    'chat_id':    TELEGRAM_CHAT,
                    'text':       (
                        f'<b>MYLO IDS — ATTAQUE DETECTEE</b>\n'
                        f'Type     : {attack_type}\n'
                        f'Severite : {severity}\n'
                        f'IP       : {attack["payload"].get("src_ip")} -> {attack["payload"].get("dst_ip")}\n'
                        f'Confiance: {confidence:.1f}%\n'
                        f'Alerte   : #{alert_id}'
                    ),
                    'parse_mode': 'HTML',
                },
                timeout=10
            )
            tg_res = tg.json()
            if tg_res.get('ok'):
                print(f"  Telegram ENVOYE (message_id: {tg_res['result']['message_id']})")
            else:
                print(f"  Telegram ECHEC : {tg_res.get('description')}")
        except Exception as e:
            print(f"  Telegram ERREUR : {e}")
    elif not is_attack:
        print(f"  Classe Normal — distribution shift NSL-KDD")
    else:
        print(f"  Severite {severity} — pas de notif Telegram (seuil HIGH/CRITICAL)")

print("\n" + "="*60)
print("  Verifie Telegram et la page Alertes !")
print("="*60)