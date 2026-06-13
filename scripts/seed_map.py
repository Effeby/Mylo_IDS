# Script pour peupler la carte avec des alertes de test réalistes
# Lance : python seed_map.py
import requests, json

DJANGO_URL = 'http://localhost:8001'

print("Connexion Django...")
r = requests.post(f'{DJANGO_URL}/api/auth/login/', json={'username':'admin','password':'mylo2025'})
token = r.json().get('access')
if not token:
    print("Erreur auth"); exit()
print("Auth OK\n")
headers = {'Authorization': f'Bearer {token}'}

# IPs publiques réelles de différents pays avec patterns d'attaque connus
FAKE_ATTACKS = [
    # DoS — Russie
    {
        'src_ip':'91.108.4.10', 'dst_ip':'10.0.0.1', 'protocol':'TCP',
        'src_bytes':0,'dst_bytes':0,'count':511,'srv_count':511,
        'serror_rate':1.0,'srv_serror_rate':1.0,'rerror_rate':0.0,
        'same_srv_rate':1.0,'diff_srv_rate':0.0,'dst_host_count':255,
        'dst_host_srv_count':255,'dst_host_same_srv_rate':1.0,
        'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':1.0,
        'dst_host_serror_rate':1.0,'dst_host_rerror_rate':0.0,
        'protocol_type':2,'flag':0,'logged_in':0,'duration':0,
        'bytes_ratio':0,'bytes_per_packet':0,'serror_diff':1.0,
        'src_port':54321,'dst_port':80,
    },
    # Probe — Chine
    {
        'src_ip':'114.114.114.10', 'dst_ip':'10.0.0.2', 'protocol':'TCP',
        'src_bytes':0,'dst_bytes':0,'count':1,'srv_count':1,
        'serror_rate':0.0,'srv_serror_rate':0.0,'rerror_rate':1.0,
        'same_srv_rate':0.0,'diff_srv_rate':1.0,'dst_host_count':255,
        'dst_host_srv_count':1,'dst_host_same_srv_rate':0.0,
        'dst_host_diff_srv_rate':1.0,'dst_host_same_src_port_rate':0.0,
        'dst_host_serror_rate':0.0,'dst_host_rerror_rate':1.0,
        'protocol_type':2,'flag':8,'logged_in':0,'duration':0,
        'bytes_ratio':0,'bytes_per_packet':0,'serror_diff':-1.0,
        'src_port':12345,'dst_port':22,
    },
    # Probe — USA (nœud Tor connu)
    {
        'src_ip':'198.51.100.7', 'dst_ip':'10.0.0.1', 'protocol':'TCP',
        'src_bytes':0,'dst_bytes':0,'count':1,'srv_count':1,
        'serror_rate':0.0,'srv_serror_rate':0.0,'rerror_rate':1.0,
        'same_srv_rate':0.0,'diff_srv_rate':1.0,'dst_host_count':255,
        'dst_host_srv_count':1,'dst_host_same_srv_rate':0.0,
        'dst_host_diff_srv_rate':1.0,'dst_host_same_src_port_rate':0.0,
        'dst_host_serror_rate':0.0,'dst_host_rerror_rate':1.0,
        'protocol_type':2,'flag':8,'logged_in':0,'duration':0,
        'bytes_ratio':0,'bytes_per_packet':0,'serror_diff':-1.0,
        'src_port':9050,'dst_port':443,
    },
    # BruteForce — Brésil
    {
        'src_ip':'177.75.40.10', 'dst_ip':'10.0.0.3', 'protocol':'TCP',
        'src_bytes':2048,'dst_bytes':512,'count':100,'srv_count':100,
        'serror_rate':0.0,'srv_serror_rate':0.0,'rerror_rate':0.8,
        'same_srv_rate':1.0,'diff_srv_rate':0.0,'dst_host_count':100,
        'dst_host_srv_count':100,'dst_host_same_srv_rate':1.0,
        'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':0.9,
        'dst_host_serror_rate':0.0,'dst_host_rerror_rate':0.8,
        'protocol_type':2,'flag':10,'logged_in':0,'duration':1,
        'bytes_ratio':4.0,'bytes_per_packet':20.48,'serror_diff':-0.8,
        'src_port':45678,'dst_port':22,
    },
    # DoS — Allemagne (nœud Tor)
    {
        'src_ip':'185.220.101.99', 'dst_ip':'10.0.0.1', 'protocol':'TCP',
        'src_bytes':0,'dst_bytes':0,'count':511,'srv_count':511,
        'serror_rate':1.0,'srv_serror_rate':1.0,'rerror_rate':0.0,
        'same_srv_rate':1.0,'diff_srv_rate':0.0,'dst_host_count':255,
        'dst_host_srv_count':255,'dst_host_same_srv_rate':1.0,
        'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':1.0,
        'dst_host_serror_rate':1.0,'dst_host_rerror_rate':0.0,
        'protocol_type':2,'flag':0,'logged_in':0,'duration':0,
        'bytes_ratio':0,'bytes_per_packet':0,'serror_diff':1.0,
        'src_port':54321,'dst_port':80,
    },
    # WebAttack — France
    {
        'src_ip':'212.83.128.10', 'dst_ip':'10.0.0.4', 'protocol':'TCP',
        'src_bytes':5000,'dst_bytes':1000,'count':50,'srv_count':50,
        'serror_rate':0.0,'srv_serror_rate':0.0,'rerror_rate':0.2,
        'same_srv_rate':1.0,'diff_srv_rate':0.0,'dst_host_count':50,
        'dst_host_srv_count':50,'dst_host_same_srv_rate':1.0,
        'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':0.5,
        'dst_host_serror_rate':0.0,'dst_host_rerror_rate':0.2,
        'protocol_type':2,'flag':10,'logged_in':0,'duration':2,
        'bytes_ratio':5.0,'bytes_per_packet':100,'serror_diff':-0.2,
        'src_port':33456,'dst_port':80,
    },
    # Botnet — Nigeria
    {
        'src_ip':'41.203.64.10', 'dst_ip':'10.0.0.2', 'protocol':'TCP',
        'src_bytes':800,'dst_bytes':400,'count':30,'srv_count':30,
        'serror_rate':0.1,'srv_serror_rate':0.1,'rerror_rate':0.1,
        'same_srv_rate':0.8,'diff_srv_rate':0.2,'dst_host_count':30,
        'dst_host_srv_count':30,'dst_host_same_srv_rate':0.8,
        'dst_host_diff_srv_rate':0.2,'dst_host_same_src_port_rate':0.3,
        'dst_host_serror_rate':0.1,'dst_host_rerror_rate':0.1,
        'protocol_type':2,'flag':10,'logged_in':0,'duration':5,
        'bytes_ratio':2.0,'bytes_per_packet':26.7,'serror_diff':0.0,
        'src_port':6667,'dst_port':443,
    },
]

print(f"Injection de {len(FAKE_ATTACKS)} alertes de test...\n")

injected = 0
for i, payload in enumerate(FAKE_ATTACKS):
    r = requests.post(
        f'{DJANGO_URL}/api/alerts/analyze/',
        json=payload,
        headers=headers
    )
    try:
        res = r.json()
        alert_id   = res.get('alert_id', '?')
        attack_type = res.get('attack_type', '?')
        is_attack  = res.get('is_attack', False)
        severity   = res.get('severity', '?')

        # Forcer is_attack=True et confirmed pour les alertes de test
        if alert_id != '?':
            requests.patch(
                f'{DJANGO_URL}/api/alerts/{alert_id}/',
                json={'status': 'confirmed'},
                headers=headers
            )
            injected += 1
            icon = '🚨' if is_attack else '📍'
            print(f"  {icon} #{alert_id} | {payload['src_ip']:20s} | {attack_type:12s} | {severity}")
    except Exception as e:
        print(f"  ✗ Erreur: {e}")

print(f"\n{'='*55}")
print(f"  {injected} alertes injectées — actualise la Threat Map !")
print(f"{'='*55}")