"""
Mylo IDS — Capture trafic réel (WiFi / SecureBank)
Capture → Features → XGBoost prédit → River apprend → Django sauvegarde
"""
import time
import requests
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ─── CONFIG ───────────────────────────────────────────────────────────
WIFI_IFACE   = r'\Device\NPF_{A6317CF1-5894-4D90-AA9D-9A6AAAE8FF74}'
DJANGO_URL   = 'http://localhost:8001'
FASTAPI_URL  = 'http://localhost:8000'
WINDOW_SEC   = 2
RIVER_AUTO_LEARN_THRESHOLD = 0.70

AUTH_TOKEN = None

PROTO_MAP = {'TCP': 2, 'UDP': 1, 'ICMP': 0, 'OTHER': 2}
FLAG_MAP  = {
    'S': 2, 'SA': 4, 'A': 10, 'FA': 6, 'R': 8, 'PA': 24,
}

flows = defaultdict(lambda: {
    'src_bytes': 0, 'dst_bytes': 0, 'count': 0,
    'srv_count': 0, 'duration': 0, 'flags': [],
    'start_time': time.time(), 'protocol': 'OTHER',
    'src_ip': '', 'dst_ip': '',
    'src_port': 0, 'dst_port': 0,   # ← nouveaux champs
    'serror_count': 0, 'rerror_count': 0,
})
lock = threading.Lock()
stats = {
    'captured': 0, 'sent': 0, 'attacks': 0,
    'river_learned': 0, 'river_skipped': 0,
}


def get_token():
    global AUTH_TOKEN
    try:
        r = requests.post(f'{DJANGO_URL}/api/auth/login/', json={
            'username': 'admin', 'password': 'mylo2025'
        }, timeout=5)
        AUTH_TOKEN = r.json().get('access')
        print("  ✓ Auth Django OK")
    except Exception as e:
        print(f"  ✗ Auth Django échouée: {e}")


def get_headers():
    return {'Authorization': f'Bearer {AUTH_TOKEN}'} if AUTH_TOKEN else {}


def packet_to_flow(pkt):
    if not pkt.haslayer(IP):
        return
    ip  = pkt[IP]
    key = f"{ip.src}→{ip.dst}"
    with lock:
        flow = flows[key]
        flow['src_ip']    = ip.src
        flow['dst_ip']    = ip.dst
        flow['src_bytes'] += len(pkt)
        flow['count']     += 1
        if pkt.haslayer(TCP):
            flow['protocol'] = 'TCP'
            flags = str(pkt[TCP].flags)
            flow['flags'].append(flags)
            flow['srv_count'] += 1
            # Capturer les ports TCP
            if flow['src_port'] == 0:
                flow['src_port'] = pkt[TCP].sport
                flow['dst_port'] = pkt[TCP].dport
            if 'S' in flags and 'A' not in flags:
                flow['serror_count'] += 1
            if 'R' in flags:
                flow['rerror_count'] += 1
        elif pkt.haslayer(UDP):
            flow['protocol'] = 'UDP'
            flow['srv_count'] += 1
            # Capturer les ports UDP
            if flow['src_port'] == 0:
                flow['src_port'] = pkt[UDP].sport
                flow['dst_port'] = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            flow['protocol'] = 'ICMP'
        flow['duration'] = time.time() - flow['start_time']
    stats['captured'] += 1


def flow_to_features(flow):
    count     = max(flow['count'], 1)
    srv_count = max(flow['srv_count'], 1)
    src_bytes = flow['src_bytes']
    dst_bytes = flow.get('dst_bytes', 0)
    duration  = max(flow['duration'], 0.001)
    serror_r  = flow['serror_count'] / count
    rerror_r  = flow['rerror_count'] / count
    flags     = flow['flags']
    flag_code = FLAG_MAP.get(max(set(flags), key=flags.count), 10) if flags else 10

    return {
        'src_bytes':                    src_bytes,
        'dst_bytes':                    dst_bytes,
        'same_srv_rate':                srv_count / count,
        'dst_host_srv_count':           min(srv_count, 255),
        'dst_host_same_srv_rate':       srv_count / count,
        'flag':                         flag_code,
        'logged_in':                    0,
        'diff_srv_rate':                0.0,
        'protocol_type':                PROTO_MAP.get(flow['protocol'], 2),
        'count':                        min(count, 511),
        'dst_host_count':               min(count, 255),
        'serror_rate':                  serror_r,
        'dst_host_serror_rate':         serror_r,
        'srv_serror_rate':              serror_r,
        'dst_host_same_src_port_rate':  0.0,
        'rerror_rate':                  rerror_r,
        'srv_count':                    min(srv_count, 511),
        'dst_host_rerror_rate':         rerror_r,
        'dst_host_diff_srv_rate':       0.0,
        'duration':                     duration,
        'bytes_ratio':                  src_bytes / (dst_bytes + 1),
        'bytes_per_packet':             src_bytes / count,
        'serror_diff':                  serror_r - rerror_r,
    }


def river_learn(features: dict, true_label: str):
    try:
        r = requests.post(
            f'{DJANGO_URL}/api/actions/river/learn/',
            json={'features': features, 'true_label': true_label},
            headers=get_headers(),
            timeout=3
        )
        if r.status_code == 200:
            result = r.json()
            stats['river_learned'] += 1
            print(f"  🧠 River [{true_label:12s}] "
                  f"{'✓' if result.get('correct') else '✗'} "
                  f"acc:{result.get('accuracy', 0):.3f} "
                  f"total:{result.get('total', 0)}")
        elif r.status_code == 401:
            get_token()
    except Exception as e:
        print(f"  ✗ River erreur: {e}")


def send_flows():
    while True:
        time.sleep(WINDOW_SEC)
        with lock:
            current_flows = dict(flows)
            flows.clear()

        if not current_flows:
            continue

        for key, flow in current_flows.items():
            if flow['count'] < 2:
                continue

            features = flow_to_features(flow)
            payload  = {
                **features,
                'src_ip':   flow['src_ip'],
                'dst_ip':   flow['dst_ip'],
                'src_port': flow['src_port'],   # ← nouveau
                'dst_port': flow['dst_port'],   # ← nouveau
                'protocol': flow['protocol'],
            }

            try:
                r = requests.post(
                    f'{DJANGO_URL}/api/alerts/analyze/',
                    json=payload,
                    headers=get_headers(),
                    timeout=3
                )
                if r.status_code == 401:
                    get_token()
                    continue
                if r.status_code != 200:
                    continue

                result       = r.json()
                is_attack    = result.get('is_attack', False)
                attack_type  = result.get('attack_type', 'Normal')
                confidence   = result.get('binary_confidence', 0)
                alert_status = result.get('alert_status', 'Nouvelle')
                stats['sent'] += 1

                src_port = flow['src_port']
                dst_port = flow['dst_port']

                if is_attack:
                    stats['attacks'] += 1
                    print(f"  🚨 {attack_type:12s} [{result.get('severity'):8s}] "
                          f"{flow['src_ip']:15s}:{src_port:<5} → "
                          f"{flow['dst_ip']:15s}:{dst_port:<5} "
                          f"conf:{confidence:.2f} [{alert_status}]")
                else:
                    print(f"  ✓  Normal        [LOW     ] "
                          f"{flow['src_ip']:15s}:{src_port:<5} → "
                          f"{flow['dst_ip']:15s}:{dst_port:<5}")

                # River apprend seulement si confiance suffisante
                if confidence >= RIVER_AUTO_LEARN_THRESHOLD:
                    true_label = attack_type if is_attack else 'Normal'
                    river_learn(features, true_label)
                else:
                    stats['river_skipped'] += 1
                    if is_attack:
                        print(f"  ⏸  River skip (conf {confidence:.2f}) → 'À vérifier'")

            except requests.exceptions.ConnectionError:
                print("  ✗ Django/FastAPI non disponible")
            except Exception as e:
                print(f"  ✗ Erreur: {e}")


def print_stats():
    while True:
        time.sleep(30)
        print(f"\n  📊 Capturés:{stats['captured']} | Envoyés:{stats['sent']} | "
              f"Attaques:{stats['attacks']} | "
              f"River appris:{stats['river_learned']} | "
              f"À vérifier:{stats['river_skipped']}\n")


if __name__ == '__main__':
    print("=" * 60)
    print("  MYLO IDS — Capture + River Online Learning")
    print("=" * 60)

    get_token()
    threading.Thread(target=send_flows, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()

    print(f"\n  Interface  : {WIFI_IFACE}")
    print(f"  Fenêtre    : {WINDOW_SEC}s")
    print(f"  River seuil: confiance ≥ {RIVER_AUTO_LEARN_THRESHOLD}")
    print(f"\n  ✓  Normal | 🚨 Attaque | 🧠 River apprend | ⏸ River skip\n")

    try:
        sniff(iface=WIFI_IFACE, prn=packet_to_flow, store=False, filter="ip")
    except KeyboardInterrupt:
        print(f"\n  Arrêt — Capturés:{stats['captured']} | "
              f"River appris:{stats['river_learned']} | "
              f"À vérifier:{stats['river_skipped']}")
        print("=" * 60)