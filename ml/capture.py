"""
Mylo — Capture trafic réel (multi-OS + DPI partiel)
Capture → Features → XGBoost prédit → River apprend → Django sauvegarde

Supporte Windows (Npcap) et Linux (root/cap_net_raw).
Les credentials sont lus depuis .env.capture
Ce fichier est créé automatiquement par Mylo au premier login admin.
"""
import time
import json
import ipaddress
import requests
import urllib3
import threading
import os
import sys
import platform
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR
from pathlib import Path

# OPNsense utilise un certificat auto-signé sur le réseau local.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── DÉTECTION OS ─────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

# ─── CONFIG ───────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
ENV_FILE   = BASE_DIR / ".env.capture"

DJANGO_URL     = os.environ.get("MYLO_DJANGO_URL", "http://localhost:8001")
_ifaces_raw    = os.environ.get("CAPTURE_IFACE", "enp0s3")
# wg0 = interface WireGuard VPN — trafic chiffré, jamais capturé (voir filtre port 51820 plus bas).
CAPTURE_IFACES = [i.strip() for i in _ifaces_raw.split(",") if i.strip().lower() != "wg0"]
WINDOW_SEC     = 2
RIVER_AUTO_LEARN_THRESHOLD = 0.70

# ─── Score de suspicion glissant par (IP source, IP dest, port dest) ──
# Complète la fenêtre courte de capture (WINDOW_SEC=2s), trop brève pour
# révéler des patterns répétitifs lents (BruteForce, Probe discret) qui
# se diluent d'une fenêtre à l'autre. Ce compteur persiste au-delà de
# chaque cycle de send_flows() et cumule le nombre de NOUVELLES CONNEXIONS
# (SYN TCP) d'une source vers UNE cible précise (IP+port), sur une fenêtre
# glissante plus large (SLIDING_WINDOW_SEC).
#
# Important : la clé inclut (dst_ip, dst_port), pas seulement src_ip.
# Une IP source normalement active (ex: un serveur qui fait DNS + HTTPS +
# heartbeat monitoring en parallèle) ne doit PAS être flaggée juste parce
# que son volume total de paquets est élevé — seul le martèlement répété
# d'UNE MÊME cible (même service) est un signal de BruteForce/Probe.
SLIDING_WINDOW_SEC   = int(os.environ.get("SLIDING_WINDOW_SEC", "60"))
SLIDING_THRESHOLD    = int(os.environ.get("SLIDING_THRESHOLD", "10"))
SLIDING_COOLDOWN_SEC = int(os.environ.get("SLIDING_COOLDOWN_SEC", "60"))
ip_activity          = defaultdict(deque)   # (src_ip,dst_ip,dst_port) -> deque[(ts, syn_count)]
ip_activity_lock     = threading.Lock()

# Anti-spam : une IP au-dessus du seuil reste au-dessus du seuil pendant
# toute la durée de l'attaque (à chaque cycle de 2s). Sans cooldown, on
# régénère une alerte "BruteForce Probable" — et donc une tentative de
# blocage OPNsense — toutes les 2 secondes tant que l'attaque continue.
sliding_alerted      = {}   # (src_ip,dst_ip,dst_port) -> timestamp de la dernière alerte
sliding_alerted_lock = threading.Lock()

# IPs de l'infrastructure Mylo — jamais alertées entre elles
INFRASTRUCTURE_IPS = {
    "173.212.241.228",  # VPS Contabo (mylo-ids.site)
    "172.16.1.94",      # BanqueAdmin (Docker host)
    "10.0.0.1",         # WireGuard gateway
    "10.0.0.2",         # VPS wg0
    "10.0.0.4",         # Windows peer WireGuard
}

INFRASTRUCTURE_PAIRS = {
    ("173.212.241.228", "172.16.1.94"),
    ("172.16.1.94", "173.212.241.228"),
    ("10.0.0.2", "172.16.1.94"),
    ("172.16.1.94", "10.0.0.2"),
    ("10.0.0.2", "10.0.0.4"),
    ("10.0.0.4", "10.0.0.2"),
}

AUTH_TOKEN = None
AUTH_USER  = None
token_lock = threading.Lock()

# ─── Mise à jour live du token (depuis Django, sans redémarrer le container) ──
UPDATE_TOKEN_PORT   = int(os.environ.get("CAPTURE_AGENT_PORT", "9999"))
CAPTURE_AGENT_SECRET = os.environ.get("CAPTURE_AGENT_SECRET", "")

# ─── OPNsense (blocage IP délégué par Django — voir /block-ip/) ──────────────
# L'agent capture tourne sur le réseau local (ex: BanqueAdmin 10.0.0.2) et
# peut donc atteindre OPNsense, contrairement à Django (hébergé sur Contabo).
OPNSENSE_URL         = os.environ.get("OPNSENSE_URL", "https://172.16.1.1").rstrip('/')
OPNSENSE_API_KEY     = os.environ.get("OPNSENSE_API_KEY", "")
OPNSENSE_API_SECRET  = os.environ.get("OPNSENSE_API_SECRET", "")
OPNSENSE_ALIAS_NAME  = os.environ.get("OPNSENSE_ALIAS_NAME", "mylo_blocklist")

PROTO_MAP = {'TCP': 2, 'UDP': 1, 'ICMP': 0, 'OTHER': 2}
FLAG_MAP  = {'S': 2, 'SA': 4, 'A': 10, 'FA': 6, 'R': 8, 'PA': 24}

# ─── Ports applicatifs connus (DPI) ───────────────────────────────────
HTTP_PORTS  = {80, 8080, 8000, 8001, 8443}
HTTPS_PORTS = {443, 8443}
DNS_PORTS   = {53}
SSH_PORTS   = {22}
FTP_PORTS   = {20, 21}
SMTP_PORTS  = {25, 465, 587}
DB_PORTS    = {3306, 5432, 1433, 27017, 6379}

flows = defaultdict(lambda: {
    'src_bytes': 0, 'dst_bytes': 0, 'count': 0,
    'srv_count': 0, 'duration': 0, 'flags': [],
    'start_time': time.time(), 'protocol': 'OTHER',
    'src_ip': '', 'dst_ip': '',
    'src_port': 0, 'dst_port': 0,
    'serror_count': 0, 'rerror_count': 0,
    # ── DPI features ──────────────────────────────────────────────────
    'payload_sizes': [],        # tailles des payloads TCP/UDP
    'app_protocol': 'UNKNOWN',  # HTTP, HTTPS, SSH, DNS, FTP, SMTP, DB, OTHER
    'has_payload': False,        # au moins un paquet avec données
    'dns_queries': [],           # noms de domaines demandés
    'tcp_syn_count': 0,          # nombre de SYN (scan détection)
    'tcp_rst_count': 0,          # nombre de RST
    'small_packet_count': 0,     # paquets < 60 octets (scan)
    'large_packet_count': 0,     # paquets > 1400 octets (exfiltration)
    'unique_dst_ports': set(),   # ports de destination distincts
    'inter_arrival_times': [],   # temps entre paquets (détection bursts)
    'last_pkt_time': None,
})
lock  = threading.Lock()
stats = {
    'captured': 0, 'sent': 0, 'attacks': 0,
    'river_learned': 0, 'river_skipped': 0,
    'dpi_http': 0, 'dpi_ssh': 0, 'dpi_dns': 0,
    'sliding_flagged': 0,
}


def detect_app_protocol(src_port: int, dst_port: int) -> str:
    """Détecte le protocole applicatif depuis les ports."""
    ports = {src_port, dst_port}
    if ports & HTTPS_PORTS:  return 'HTTPS'
    if ports & HTTP_PORTS:   return 'HTTP'
    if ports & SSH_PORTS:    return 'SSH'
    if ports & DNS_PORTS:    return 'DNS'
    if ports & FTP_PORTS:    return 'FTP'
    if ports & SMTP_PORTS:   return 'SMTP'
    if ports & DB_PORTS:     return 'DATABASE'
    return 'OTHER'


# ─── Score de suspicion glissant par (IP source, IP dest, port dest) ──
def record_ip_activity(target_key: tuple, amount: int):
    """
    Enregistre le nombre de nouvelles connexions (SYN) d'une source vers
    UNE cible précise (src_ip, dst_ip, dst_port), pour le score de
    suspicion glissant qui persiste au-delà d'une seule fenêtre de
    capture de WINDOW_SEC secondes.
    """
    if amount <= 0:
        return
    now = time.time()
    with ip_activity_lock:
        dq = ip_activity[target_key]
        dq.append((now, amount))
        cutoff = now - SLIDING_WINDOW_SEC
        while dq and dq[0][0] < cutoff:
            dq.popleft()


def get_ip_suspicion_score(target_key: tuple) -> int:
    """
    Retourne le nombre cumulé de nouvelles connexions d'une source vers
    une cible précise sur la fenêtre glissante SLIDING_WINDOW_SEC (purge
    les entrées expirées au passage).
    """
    now = time.time()
    cutoff = now - SLIDING_WINDOW_SEC
    with ip_activity_lock:
        dq = ip_activity[target_key]
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return sum(amount for _, amount in dq)


def sliding_cooldown_ok(target_key: tuple) -> bool:
    """
    Anti-spam : retourne True seulement si le cooldown est écoulé pour
    cette cible, ce qui autorise une (nouvelle) alerte "BruteForce
    Probable" — et donc une tentative de blocage OPNsense. Sans ce
    garde-fou, le score glissant reste au-dessus du seuil pendant toute
    la durée de l'attaque, régénérant une alerte à CHAQUE cycle de
    WINDOW_SEC (2s), ce qui spamme le dashboard et retente le blocage
    en boucle inutilement.
    """
    now = time.time()
    with sliding_alerted_lock:
        # purge opportuniste des entrées très anciennes (évite une
        # croissance illimitée du dict sur une longue durée de service)
        stale_cutoff = now - (SLIDING_COOLDOWN_SEC * 10)
        for k in [k for k, ts in sliding_alerted.items() if ts < stale_cutoff]:
            del sliding_alerted[k]

        last = sliding_alerted.get(target_key, 0)
        if now - last >= SLIDING_COOLDOWN_SEC:
            sliding_alerted[target_key] = now
            return True
        return False


def resolve_windows_interfaces():
    """
    Sur Windows, CAPTURE_IFACE peut contenir des noms lisibles (Wi-Fi, Ethernet)
    ou des GUIDs. Scapy sur Windows attend les GUIDs NPF.
    On tente de résoudre automatiquement.
    """
    if not IS_WINDOWS:
        return CAPTURE_IFACES

    try:
        from scapy.arch.windows import get_windows_if_list
        win_ifaces = get_windows_if_list()

        resolved = []
        for iface_name in CAPTURE_IFACES:
            matched = False
            for wi in win_ifaces:
                # Correspondance sur le nom, description ou GUID
                if (iface_name.lower() in wi.get('name', '').lower() or
                    iface_name.lower() in wi.get('description', '').lower() or
                    iface_name in wi.get('guid', '')):
                    resolved.append(wi['name'])
                    matched = True
                    break
            if not matched:
                # Garder tel quel (peut-être déjà un GUID)
                resolved.append(iface_name)

        if resolved:
            print(f"  [Windows] Interfaces résolues : {resolved}")
            return resolved
    except Exception as e:
        print(f"  ⚠  Résolution interfaces Windows échouée: {e}")

    return CAPTURE_IFACES


def check_privileges():
    """Vérifie les droits nécessaires selon l'OS."""
    if IS_LINUX:
        if os.geteuid() != 0:
            print("  ✗ Linux : la capture réseau nécessite les droits root.")
            print("    Lance avec : sudo python ml/capture.py")
            print("    Ou via Docker avec cap_add: [NET_ADMIN, NET_RAW]")
            sys.exit(1)
    elif IS_WINDOWS:
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("  ⚠  Windows : lance PowerShell en Administrateur pour capturer.")
                print("    Npcap doit être installé : https://npcap.com/")
        except Exception:
            pass


def read_env_capture():
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    return env


def get_token():
    global AUTH_TOKEN, AUTH_USER
    env = read_env_capture()

    # Priorité : token JWT direct (généré après login TOTP)
    capture_token = env.get('CAPTURE_TOKEN')
    if capture_token:
        AUTH_TOKEN = capture_token
        print(f"  ✓ Auth via token JWT capture")
        return

    # Fallback : login classique (sans TOTP)
    username = env.get('CAPTURE_USERNAME')
    password = env.get('CAPTURE_PASSWORD')
    if not username or not password:
        print(f"  ⚠  Credentials manquants dans {ENV_FILE}")
        print(f"  💡 Connecte-toi à Mylo — les credentials seront sauvegardées automatiquement.")
        return
    try:
        r = requests.post(f'{DJANGO_URL}/api/auth/login/', json={
            'username': username, 'password': password
        }, timeout=10)
        if r.ok:
            AUTH_TOKEN = r.json().get('access')
            AUTH_USER  = username
            org = r.json().get('user', {}).get('organisation', {}).get('name', '?')
            print(f"  ✓ Auth Django OK — {username} ({org})")
        else:
            print(f"  ✗ Auth échouée ({r.status_code})")
    except Exception as e:
        print(f"  ✗ Auth Django échouée: {e}")


def get_headers():
    return {'Authorization': f'Bearer {AUTH_TOKEN}'} if AUTH_TOKEN else {}


# ─── Découverte réseau locale (ARP + Nmap) — exécutée par l'agent ─────────────
def arp_scan_local(target_cidr: str) -> list:
    """Scan ARP actif sur le segment réseau local de l'agent."""
    from scapy.all import ARP, Ether, srp

    arp    = ARP(pdst=target_cidr)
    ether  = Ether(dst='ff:ff:ff:ff:ff:ff')
    result = srp(ether / arp, timeout=3, verbose=0)[0]
    return [{'ip': r.psrc, 'mac': r.hwsrc} for _, r in result]


def nmap_fingerprint_local(ip: str) -> dict:
    """Fingerprinting Nmap (OS, ports ouverts, services) sur une IP."""
    import nmap

    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O -sV --top-ports 20 --host-timeout 10s')
    if ip not in nm.all_hosts():
        return {}

    host = nm[ip]
    os_type = ''
    if 'osmatch' in host and host['osmatch']:
        os_type = host['osmatch'][0].get('name', '')

    open_ports = []
    services   = {}
    for proto in host.all_protocols():
        for port in host[proto].keys():
            info = host[proto][port]
            if info['state'] == 'open':
                open_ports.append(port)
                services[port] = info.get('name', '') + (
                    f" {info.get('product', '')} {info.get('version', '')}".strip()
                )

    return {'os_type': os_type, 'open_ports': open_ports, 'services': services}


def discover_local(target_cidr: str) -> list:
    """ARP scan + fingerprint Nmap (en parallèle) sur le réseau local de l'agent."""
    clients = arp_scan_local(target_cidr)
    if not clients:
        return []

    results = {}

    def _fingerprint(client):
        ip   = client['ip']
        info = nmap_fingerprint_local(ip)
        results[ip] = {**client, **info}

    threads = [threading.Thread(target=_fingerprint, args=(c,)) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return list(results.values())


# ─── Blocage OPNsense local (délégué par Django via /block-ip/) ─────────────
def opnsense_block_ip(ip: str, raison: str = "Mylo IPS — auto") -> dict:
    """
    Ajoute une IP à l'alias blocklist OPNsense, en appelant l'API OPNsense
    directement depuis ce réseau local (voir alerts/opnsense_client.py côté
    Django pour la même logique, dupliquée ici car cet agent est un script
    autonome sans Django).
    """
    if not OPNSENSE_API_KEY:
        return {'success': False, 'message': "OPNsense non configuré sur l'agent (OPNSENSE_API_KEY manquant)"}

    auth = (OPNSENSE_API_KEY, OPNSENSE_API_SECRET)

    def _get(endpoint):
        r = requests.get(f"{OPNSENSE_URL}/api/{endpoint}", auth=auth, verify=False, timeout=5)
        r.raise_for_status()
        return r.json()

    def _post(endpoint, data=None):
        r = requests.post(f"{OPNSENSE_URL}/api/{endpoint}", json=data or {}, auth=auth, verify=False, timeout=5)
        r.raise_for_status()
        return r.json()

    try:
        alias_result = _get(f"firewall/alias/getAliasUUID/{OPNSENSE_ALIAS_NAME}")
        alias_uuid = alias_result.get('uuid')

        if not alias_uuid:
            create_result = _post("firewall/alias/addItem", {
                "alias": {
                    "name":        OPNSENSE_ALIAS_NAME,
                    "type":        "host",
                    "content":     ip,
                    "description": f"Mylo IPS blocklist — {raison}"
                }
            })
            alias_uuid = create_result.get('uuid')
        else:
            alias_data    = _get(f"firewall/alias/getItem/{alias_uuid}")
            content_actuel = alias_data.get('alias', {}).get('content', {})
            ips_actuelles = [
                v.get('value', '')
                for v in content_actuel.values()
                if isinstance(v, dict)
            ] if isinstance(content_actuel, dict) else []

            if ip in ips_actuelles:
                return {'success': True, 'message': f'{ip} déjà dans la blocklist', 'already_blocked': True}

            ips_actuelles.append(ip)
            _post(f"firewall/alias/setItem/{alias_uuid}", {
                "alias": {
                    "name":        OPNSENSE_ALIAS_NAME,
                    "type":        "host",
                    "content":     "\n".join(ips_actuelles),
                    "description": "Mylo IPS blocklist"
                }
            })

        _post("firewall/alias/reconfigure")
        _post("firewall/filter/apply")

        return {'success': True, 'message': f'IP {ip} bloquée sur OPNsense (via agent capture)', 'ip': ip}

    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': f'OPNsense inaccessible depuis l\'agent — vérifie {OPNSENSE_URL}'}
    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'OPNsense timeout depuis l\'agent'}
    except Exception as e:
        return {'success': False, 'message': f'Erreur OPNsense: {e}'}


# ─── Mini serveur HTTP — token live + découverte réseau (stdlib uniquement) ──
class TokenUpdateHandler(BaseHTTPRequestHandler):
    """
    Expose :
    - POST /update-token/ pour que Django pousse un nouveau token JWT
      (après login TOTP) sans avoir à redémarrer le container de capture.
    - POST /discover/ pour que Django délègue la découverte réseau (ARP/Nmap)
      à l'agent, qui lui est bien sur le réseau local de la cible.
    - POST /block-ip/ pour que Django délègue le blocage OPNsense à l'agent,
      qui lui est bien sur le réseau local d'OPNsense.
    """

    def log_message(self, format, *args):
        pass  # silence les logs HTTP par défaut (garde la sortie capture.py lisible)

    def _send_json(self, status_code: int, payload: dict):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_secret(self) -> bool:
        if CAPTURE_AGENT_SECRET:
            if self.headers.get('X-Capture-Secret') != CAPTURE_AGENT_SECRET:
                self._send_json(401, {'error': 'unauthorized'})
                return False
        return True

    def _read_json_body(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        raw    = self.rfile.read(length) if length else b'{}'
        return json.loads(raw or b'{}')

    def do_POST(self):
        global AUTH_TOKEN

        path = self.path.rstrip('/')

        if path == '/update-token':
            if not self._check_secret():
                return
            try:
                data  = self._read_json_body()
                token = data.get('token')
            except Exception:
                self._send_json(400, {'error': 'invalid JSON'})
                return

            if not token:
                self._send_json(400, {'error': 'token requis'})
                return

            with token_lock:
                AUTH_TOKEN = token
            # Réponse envoyée avant le log : un souci d'encodage console ne doit
            # jamais empêcher la confirmation HTTP de partir.
            self._send_json(200, {'status': 'ok'})
            try:
                print("  🔑 Token capture mis à jour en direct via /update-token/")
            except Exception:
                pass
            return

        if path == '/discover':
            if not self._check_secret():
                return
            try:
                data = self._read_json_body()
                cidr = data.get('cidr')
            except Exception:
                self._send_json(400, {'error': 'invalid JSON'})
                return

            if not cidr:
                self._send_json(400, {'error': 'cidr requis'})
                return

            try:
                devices = discover_local(cidr)
            except Exception as e:
                self._send_json(500, {'error': f'Erreur découverte : {e}'})
                return

            self._send_json(200, {'devices': devices})
            try:
                print(f"  🔍 Découverte réseau via /discover/ — {len(devices)} hôte(s) sur {cidr}")
            except Exception:
                pass
            return

        if path == '/block-ip':
            if not self._check_secret():
                return
            try:
                data = self._read_json_body()
                ip   = data.get('ip')
            except Exception:
                self._send_json(400, {'error': 'invalid JSON'})
                return

            if not ip:
                self._send_json(400, {'error': 'ip requis'})
                return
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self._send_json(400, {'error': 'ip invalide'})
                return

            result = opnsense_block_ip(ip)
            self._send_json(200 if result.get('success') else 502, result)
            try:
                print(f"  🛑 Blocage IP via /block-ip/ — {ip}: {result.get('message')}")
            except Exception:
                pass
            return

        self._send_json(404, {'error': 'not found'})


def start_token_update_server():
    try:
        server = ThreadingHTTPServer(('0.0.0.0', UPDATE_TOKEN_PORT), TokenUpdateHandler)
        print(f"  🔌 Agent update-token en écoute sur 0.0.0.0:{UPDATE_TOKEN_PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"  ✗ Agent update-token indisponible: {e}")


def packet_to_flow(pkt):
    if not pkt.haslayer(IP):
        return

    ip  = pkt[IP]

    # Ignorer silencieusement le trafic interne infra
    if (ip.src, ip.dst) in INFRASTRUCTURE_PAIRS:
        return

    # Ignorer les flux où les deux extrémités sont de l'infra
    if ip.src in INFRASTRUCTURE_IPS and ip.dst in INFRASTRUCTURE_IPS:
        return

    key = f"{ip.src}→{ip.dst}"
    pkt_len = len(pkt)
    now = time.time()

    with lock:
        flow = flows[key]
        flow['src_ip']    = ip.src
        flow['dst_ip']    = ip.dst
        flow['src_bytes'] += pkt_len
        flow['count']     += 1

        # ── Inter-arrival time ────────────────────────────────────────
        if flow['last_pkt_time'] is not None:
            iat = now - flow['last_pkt_time']
            flow['inter_arrival_times'].append(iat)
        flow['last_pkt_time'] = now

        # ── Taille paquets ────────────────────────────────────────────
        if pkt_len < 60:
            flow['small_packet_count'] += 1
        elif pkt_len > 1400:
            flow['large_packet_count'] += 1

        if pkt.haslayer(TCP):
            flow['protocol'] = 'TCP'
            tcp = pkt[TCP]
            flags = str(tcp.flags)
            flow['flags'].append(flags)
            flow['srv_count'] += 1

            if flow['src_port'] == 0:
                flow['src_port'] = tcp.sport
                flow['dst_port'] = tcp.dport
                flow['app_protocol'] = detect_app_protocol(tcp.sport, tcp.dport)

            flow['unique_dst_ports'].add(tcp.dport)

            if 'S' in flags and 'A' not in flags:
                flow['serror_count'] += 1
                flow['tcp_syn_count'] += 1
            if 'R' in flags:
                flow['rerror_count'] += 1
                flow['tcp_rst_count'] += 1

            # ── Payload TCP ───────────────────────────────────────────
            if pkt.haslayer(Raw):
                raw_data = pkt[Raw].load
                payload_size = len(raw_data)
                flow['payload_sizes'].append(payload_size)
                flow['has_payload'] = True

        elif pkt.haslayer(UDP):
            flow['protocol'] = 'UDP'
            udp = pkt[UDP]
            flow['srv_count'] += 1

            if flow['src_port'] == 0:
                flow['src_port'] = udp.sport
                flow['dst_port'] = udp.dport
                flow['app_protocol'] = detect_app_protocol(udp.sport, udp.dport)

            flow['unique_dst_ports'].add(udp.dport)

            # ── DNS query extraction ──────────────────────────────────
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    if qname:
                        flow['dns_queries'].append(qname)
                        flow['app_protocol'] = 'DNS'
                except Exception:
                    pass

            if pkt.haslayer(Raw):
                flow['payload_sizes'].append(len(pkt[Raw].load))
                flow['has_payload'] = True

        elif pkt.haslayer(ICMP):
            flow['protocol'] = 'ICMP'

        flow['duration'] = now - flow['start_time']

    stats['captured'] += 1


def flow_to_features(flow):
    """Convertit un flow en features + enrichit avec DPI."""
    count     = max(flow['count'], 1)
    srv_count = max(flow['srv_count'], 1)
    src_bytes = flow['src_bytes']
    dst_bytes = flow.get('dst_bytes', 0)
    duration  = max(flow['duration'], 0.001)
    serror_r  = flow['serror_count'] / count
    rerror_r  = flow['rerror_count'] / count
    flags     = flow['flags']
    flag_code = FLAG_MAP.get(max(set(flags), key=flags.count), 10) if flags else 10

    # ── Features DPI ──────────────────────────────────────────────────
    payload_sizes = flow['payload_sizes']
    avg_payload   = sum(payload_sizes) / len(payload_sizes) if payload_sizes else 0
    max_payload   = max(payload_sizes) if payload_sizes else 0
    unique_ports  = len(flow['unique_dst_ports'])

    iats = flow['inter_arrival_times']
    avg_iat = sum(iats) / len(iats) if iats else 0

    # Score de suspicion DPI (0.0 → 1.0)
    dpi_suspicion = 0.0
    dpi_reasons   = []

    # Scan de ports : beaucoup de ports distincts en peu de paquets
    if unique_ports > 10 and count < 50:
        dpi_suspicion += 0.3
        dpi_reasons.append(f"port_scan({unique_ports} ports)")

    # SYN flood : beaucoup de SYN sans ACK
    syn_ratio = flow['tcp_syn_count'] / count if count > 0 else 0
    if syn_ratio > 0.8 and count > 20:
        dpi_suspicion += 0.4
        dpi_reasons.append(f"syn_flood(ratio={syn_ratio:.2f})")

    # Paquets minuscules en masse (Nmap, scanning)
    small_ratio = flow['small_packet_count'] / count
    if small_ratio > 0.7 and count > 10:
        dpi_suspicion += 0.2
        dpi_reasons.append(f"small_pkts({small_ratio:.2f})")

    # Gros volumes sortants (exfiltration potentielle)
    if src_bytes > 5_000_000 and avg_payload > 800:
        dpi_suspicion += 0.3
        dpi_reasons.append(f"large_transfer({src_bytes//1024}KB)")

    # Bursts (trafic très irrégulier = DDoS)
    if len(iats) > 5:
        import statistics
        try:
            iat_stdev = statistics.stdev(iats)
            if iat_stdev > 1.0 and count > 30:
                dpi_suspicion += 0.2
                dpi_reasons.append(f"burst(stdev={iat_stdev:.2f})")
        except Exception:
            pass

    dpi_suspicion = min(dpi_suspicion, 1.0)

    # Mise à jour stats DPI
    if flow['app_protocol'] == 'HTTP':  stats['dpi_http'] += 1
    if flow['app_protocol'] == 'SSH':   stats['dpi_ssh'] += 1
    if flow['app_protocol'] == 'DNS':   stats['dpi_dns'] += 1

    features = {
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
        # ── DPI enrichissement (envoyé à Django pour log) ─────────────
        '_dpi_app_protocol':    flow['app_protocol'],
        '_dpi_suspicion':       round(dpi_suspicion, 3),
        '_dpi_reasons':         ', '.join(dpi_reasons) if dpi_reasons else '',
        '_dpi_unique_ports':    unique_ports,
        '_dpi_avg_payload':     round(avg_payload, 1),
        '_dpi_max_payload':     max_payload,
        '_dpi_syn_ratio':       round(syn_ratio, 3),
        '_dpi_small_ratio':     round(small_ratio, 3),
        '_dpi_avg_iat':         round(avg_iat, 4),
        '_dpi_dns_queries':     flow['dns_queries'][:5],  # max 5
        '_dpi_has_payload':     flow['has_payload'],
    }

    return features


def river_learn(features: dict, true_label: str):
    # Exclure les champs DPI du payload River
    clean = {k: v for k, v in features.items() if not k.startswith('_dpi')}
    try:
        r = requests.post(
            f'{DJANGO_URL}/api/actions/river/learn/',
            json={'features': clean, 'true_label': true_label},
            headers=get_headers(),
            timeout=10
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

        if not AUTH_TOKEN:
            get_token()
            continue

        try:
            phase_resp = requests.get(
                f'{DJANGO_URL}/api/alerts/baseline/phase/',
                headers=get_headers(), timeout=10
            )
            phase_data        = phase_resp.json() if phase_resp.ok else {}
            phase_actuelle    = phase_data.get('phase', 'production')
            river_learn_threshold = phase_data.get('river_threshold', RIVER_AUTO_LEARN_THRESHOLD)
        except Exception:
            phase_actuelle        = 'production'
            river_learn_threshold = RIVER_AUTO_LEARN_THRESHOLD

        for key, flow in current_flows.items():
            if flow['count'] < 2:
                continue

            # Trafic WireGuard VPN (port 51820) : chiffré, inanalysable au niveau
            # applicatif → faux positifs systématiques. On l'ignore silencieusement.
            if flow['src_port'] == 51820 or flow['dst_port'] == 51820:
                continue

            # ── Score de suspicion glissant ─────────────────────────────
            # Enregistre uniquement le nombre de NOUVELLES CONNEXIONS (SYN)
            # de cette source vers CETTE cible précise (IP+port), pas le
            # volume brut de paquets — sinon toute IP simplement active
            # (DNS, navigation, heartbeat) serait flaggée à tort.
            # N'a de sens que pour TCP (notion de "tentative de connexion").
            bruteforce_score = 0
            target_key = None
            if flow['protocol'] == 'TCP' and flow['tcp_syn_count'] > 0:
                target_key = (flow['src_ip'], flow['dst_ip'], flow['dst_port'])
                record_ip_activity(target_key, flow['tcp_syn_count'])
                bruteforce_score = get_ip_suspicion_score(target_key)

            features = flow_to_features(flow)

            # Payload envoyé à Django (sans les champs DPI internes)
            clean_features = {k: v for k, v in features.items() if not k.startswith('_dpi')}
            payload = {
                **clean_features,
                'src_ip':   flow['src_ip'],
                'dst_ip':   flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                # DPI metadata pour enrichissement Django
                'dpi_app_protocol': features.get('_dpi_app_protocol', 'UNKNOWN'),
                'dpi_suspicion':    features.get('_dpi_suspicion', 0.0),
                'dpi_reasons':      features.get('_dpi_reasons', ''),
                'dpi_unique_ports': features.get('_dpi_unique_ports', 0),
                'dpi_dns_queries':  features.get('_dpi_dns_queries', []),
            }

            threading.Thread(
                target=analyze_flow_async,
                args=(payload, features, flow, phase_actuelle, river_learn_threshold, bruteforce_score, target_key),
                daemon=True
            ).start()


def analyze_flow_async(payload, features, flow, phase_actuelle, river_learn_threshold, bruteforce_score=0, target_key=None):
    try:
        r = requests.post(
            f'{DJANGO_URL}/api/alerts/analyze/',
            json=payload,
            headers=get_headers(),
            timeout=15
        )
        if r.status_code == 401:
            get_token()
            return
        if r.status_code != 200:
            return

        result       = r.json()
        is_attack    = result.get('is_attack', False)
        attack_type  = result.get('attack_type', 'Normal')
        confidence   = result.get('binary_confidence', 0)
        alert_status = result.get('alert_status', 'Nouvelle')
        if_triggered = result.get('if_triggered', False)
        dpi_susp     = features.get('_dpi_suspicion', 0.0)
        dpi_reasons  = features.get('_dpi_reasons', '')
        app_proto    = features.get('_dpi_app_protocol', '')
        stats['sent'] += 1

        src_port = flow['src_port']
        dst_port = flow['dst_port']

        # ── DPI override : suspicion élevée même si ML dit Normal
        if not is_attack and dpi_susp >= 0.5:
            is_attack   = True
            attack_type = "Anomalie"
            alert_status = "À vérifier"
            print(f"  🔍 DPI [{app_proto:8s}] suspicion={dpi_susp:.2f} "
                  f"{flow['src_ip']}:{src_port} → {flow['dst_ip']}:{dst_port} "
                  f"[{dpi_reasons}]")

        # ── Sliding-window override : BruteForce probable sur pattern lent ──
        # XGBoost/Scapy raisonnent sur une fenêtre courte (WINDOW_SEC=2s), donc
        # une attaque lente et répétée (ex: BruteForce ~1 tentative/s) se dilue
        # d'une fenêtre à l'autre et reste sous le radar. Ce compteur persistant
        # par (src,dst,port), cumulé sur SLIDING_WINDOW_SEC, rattrape ce cas.
        #
        # Le cooldown (sliding_cooldown_ok) évite de régénérer l'alerte — et
        # donc de retenter le blocage OPNsense — à chaque cycle de 2s tant
        # que l'attaque continue : une seule alerte par cible et par fenêtre
        # de SLIDING_COOLDOWN_SEC suffit.
        if (not is_attack and bruteforce_score >= SLIDING_THRESHOLD
                and target_key is not None and sliding_cooldown_ok(target_key)):
            is_attack    = True
            attack_type  = "BruteForce Probable"
            alert_status = "À vérifier"
            stats['sliding_flagged'] += 1
            print(f"  ⏱️  SLIDING [{SLIDING_WINDOW_SEC}s] score={bruteforce_score} "
                  f"{flow['src_ip']}:{src_port} → {flow['dst_ip']}:{dst_port} "
                  f"— BruteForce probable")

        if is_attack:
            stats['attacks'] += 1
            if_tag = " [IF🎯]" if if_triggered else ""
            print(f"  🚨 {attack_type:12s} [{result.get('severity', 'HIGH'):8s}]{if_tag} "
                  f"{flow['src_ip']:15s}:{src_port:<5} → "
                  f"{flow['dst_ip']:15s}:{dst_port:<5} "
                  f"conf:{confidence:.2f} [{alert_status}] "
                  f"app:{app_proto}")
        else:
            print(f"  ✓  Normal        [LOW     ] "
                  f"{flow['src_ip']:15s}:{src_port:<5} → "
                  f"{flow['dst_ip']:15s}:{dst_port:<5} "
                  f"app:{app_proto}")

        # ── River gated par phase ─────────────────────────────
        river_doit_apprendre = False
        if phase_actuelle == 'learning':
            if not is_attack:
                river_doit_apprendre = True
                print(f"  📚 River [LEARNING] apprend trafic Normal")
            else:
                print(f"  📚 River [LEARNING] skip attaque")
        elif phase_actuelle == 'validation':
            print(f"  ⏳ River [VALIDATION] en attente admin")
        elif phase_actuelle == 'production':
            if confidence >= river_learn_threshold:
                river_doit_apprendre = True
            else:
                stats['river_skipped'] += 1
                if is_attack:
                    print(f"  ⏸  River skip (conf {confidence:.2f})")

        if river_doit_apprendre:
            true_label = attack_type if is_attack else 'Normal'
            river_learn(features, true_label)

    except requests.exceptions.Timeout:
        pass
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
              f"À vérifier:{stats['river_skipped']} | "
              f"Sliding flagged:{stats['sliding_flagged']} | "
              f"DPI HTTP:{stats['dpi_http']} SSH:{stats['dpi_ssh']} DNS:{stats['dpi_dns']}\n")


if __name__ == '__main__':
    print("=" * 60)
    print("  Mylo IPS — Capture + DPI + River Online Learning")
    print(f"  OS détecté : {platform.system()}")
    print("=" * 60)

    check_privileges()

    # Résolution interfaces selon OS
    active_ifaces = resolve_windows_interfaces()

    get_token()
    threading.Thread(target=send_flows, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    threading.Thread(target=start_token_update_server, daemon=True).start()

    print(f"  Interfaces : {', '.join(active_ifaces)}")
    print(f"  Fenêtre    : {WINDOW_SEC}s")
    print(f"  Sliding    : {SLIDING_WINDOW_SEC}s, seuil={SLIDING_THRESHOLD}")
    print(f"  River seuil: confiance ≥ {RIVER_AUTO_LEARN_THRESHOLD}")
    print(f"  DPI        : port scan, SYN flood, exfiltration, bursts, DNS")
    print(f"\n  ✓ Normal | 🚨 Attaque | 🔍 DPI | ⏱️  Sliding | 🎯 IF zero-day | 🧠 River\n")

    if IS_WINDOWS:
        print("  ⚠  Windows : assure-toi que Npcap est installé (https://npcap.com/)")
        print("  ⚠  Lance PowerShell en Administrateur\n")

    try:
        sniff(iface=active_ifaces, prn=packet_to_flow, store=False, filter="ip and not src host 0.0.0.0")
    except PermissionError:
        print("\n  ✗ Permission refusée.")
        if IS_LINUX:
            print("    Lance avec : sudo python ml/capture.py")
        else:
            print("    Lance PowerShell en Administrateur")
    except Exception as e:
        print(f"\n  ✗ Erreur sniff: {e}")
        if IS_WINDOWS:
            print("    Installe Npcap : https://npcap.com/")
    finally:
        print(f"\n  Arrêt — Capturés:{stats['captured']} | "
              f"River appris:{stats['river_learned']} | "
              f"À vérifier:{stats['river_skipped']}")
        print("=" * 60)