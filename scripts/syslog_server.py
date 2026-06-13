#!/usr/bin/env python
"""
Mylo IPS — Serveur Syslog UDP
Place dans D:/MYLO/scripts/
Lance automatiquement via start_mylo.py

Écoute sur UDP 5140
Parse les logs OPNsense, Suricata, Linux, Windows AD
Charge la config des sources depuis l'API Django (dynamique)
"""
import socket
import re
import json
import threading
import requests
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────
SYSLOG_PORT   = int(os.environ.get('SYSLOG_PORT', 5140))
DJANGO_URL    = os.environ.get('DJANGO_URL', 'http://localhost:8001')
BUFFER_SIZE   = 4096
MAX_QUEUE     = 1000
RELOAD_EVERY  = 60  # Recharger SOURCE_MAP depuis Django toutes les 60s

# ── SOURCE_MAP chargé dynamiquement depuis Django ─────────────────────
# Format : { 'ip': { org_id, vlan_id, vlan_name, source_type, name } }
SOURCE_MAP  = {}
map_lock    = threading.Lock()
django_token = None  # Token JWT service account


def _read_env_capture():
    base_dir = Path(__file__).resolve().parent.parent
    env_file = base_dir / '.env.capture'
    env = {}
    if env_file.exists():
        for line in env_file.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    return env


def get_django_token(retries=5, delay=3):
    """Se connecter à Django pour obtenir un token. Réessaie si Django pas encore prêt."""
    global django_token
    env      = _read_env_capture()
    username = env.get('CAPTURE_USERNAME') or os.environ.get('MYLO_USER', 'admin')
    password = env.get('CAPTURE_PASSWORD') or os.environ.get('MYLO_PASS', 'mylo2025')

    for attempt in range(retries):
        try:
            r = requests.post(
                f'{DJANGO_URL}/api/auth/login/',
                json={'username': username, 'password': password},
                timeout=5,
            )
            if r.ok:
                django_token = r.json().get('access')
                org = r.json().get('user', {}).get('organisation', {}).get('name', '?')
                print(f"  ✓ Authentifié sur Django ({username} — {org})")
                return
            else:
                print(f"  ⚠ Auth Django échouée: {r.status_code}")
                return
        except Exception:
            if attempt < retries - 1:
                print(f"  ⏳ Django pas encore prêt, nouvelle tentative dans {delay}s... ({attempt+1}/{retries})")
                time.sleep(delay)
            else:
                print(f"  ⚠ Django inaccessible après {retries} tentatives")


def reload_source_map():
    """Charge les sources Syslog depuis Django toutes les 60s."""
    global SOURCE_MAP
    while True:
        try:
            if not django_token:
                get_django_token()

            headers = {}
            if django_token:
                headers['Authorization'] = f'Bearer {django_token}'

            # Récupérer toutes les sources de toutes les orgs
            # (le syslog server est global, il reçoit les logs de tous les tenants)
            r = requests.get(
                f'{DJANGO_URL}/api/alerts/syslog-sources/?format=map&all=true',
                headers=headers,
                timeout=5,
            )
            if r.ok:
                new_map = r.json()
                with map_lock:
                    SOURCE_MAP = new_map
                print(f"  🔄 SOURCE_MAP rechargé — {len(new_map)} sources configurées")
            else:
                print(f"  ⚠ Impossible de charger SOURCE_MAP: {r.status_code}")
        except Exception as e:
            print(f"  ⚠ Erreur reload SOURCE_MAP: {e}")

        time.sleep(RELOAD_EVERY)


# ─── PARSERS ──────────────────────────────────────────────────────────

def parse_priority(raw):
    match = re.match(r'<(\d+)>', raw)
    if match:
        pri      = int(match.group(1))
        facility = pri >> 3
        severity = pri & 7
        return pri, facility, severity
    return 0, 16, 6


def detect_source_info(source_ip, program, message):
    """Récupère les infos de la source depuis SOURCE_MAP."""
    with map_lock:
        info = SOURCE_MAP.get(source_ip)

    if info:
        return info

    # Auto-détection si IP inconnue
    prog = (program or '').lower()
    msg  = (message or '').lower()
    source_type = 'unknown'
    if 'filterlog' in prog or 'opnsense' in msg: source_type = 'opnsense'
    elif 'suricata' in prog:                      source_type = 'suricata'
    elif 'sshd' in prog or 'sudo' in prog:        source_type = 'linux'
    elif 'security' in prog:                      source_type = 'windows_ad'

    return {
        'org_id':      None,
        'vlan_id':     None,
        'vlan_name':   '',
        'source_type': source_type,
        'name':        source_ip,
    }


def parse_opnsense(message):
    parsed = {}
    try:
        if ',' in message and message.count(',') > 8:
            parts = message.split(',')
            if len(parts) >= 13:
                parsed['action']    = parts[6]
                parsed['direction'] = parts[7]
                parsed['interface'] = parts[4]
                if len(parts) >= 19:
                    parsed['src_ip']   = parts[12]
                    parsed['dst_ip']   = parts[13]
                    parsed['src_port'] = parts[17] if len(parts) > 17 else ''
                    parsed['dst_port'] = parts[18] if len(parts) > 18 else ''
                parsed['rule']     = parts[0]
                if parsed.get('action', '').lower() in ('block', 'reject'):
                    parsed['threat_hint'] = 'firewall_block'
    except Exception as e:
        parsed['parse_error'] = str(e)
    return parsed


def parse_suricata(message):
    parsed = {}
    try:
        data = json.loads(message)
        parsed.update({
            'event_type': data.get('event_type'),
            'src_ip':     data.get('src_ip'),
            'dst_ip':     data.get('dest_ip'),
            'src_port':   data.get('src_port'),
            'dst_port':   data.get('dest_port'),
            'protocol':   data.get('proto'),
        })
        if data.get('event_type') == 'alert':
            alert = data.get('alert', {})
            parsed.update({
                'signature':    alert.get('signature'),
                'category':     alert.get('category'),
                'threat_hint':  'ids_alert',
            })
    except json.JSONDecodeError:
        sig_match = re.search(r'\[.*?\]\s+(.+?)\s+\[', message)
        if sig_match:
            parsed['signature']   = sig_match.group(1)
            parsed['threat_hint'] = 'ids_alert'
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)', message)
        if ip_match:
            parsed.update({'src_ip': ip_match.group(1), 'src_port': ip_match.group(2),
                           'dst_ip': ip_match.group(3), 'dst_port': ip_match.group(4)})
    except Exception as e:
        parsed['parse_error'] = str(e)
    return parsed


def parse_linux(program, message):
    parsed = {'program': program}
    msg = message.lower()
    try:
        if 'sshd' in program.lower():
            if 'failed password' in msg or 'invalid user' in msg:
                user_match = re.search(r'(?:for|user)\s+(\S+)', message, re.I)
                ip_match   = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
                parsed.update({
                    'event': 'ssh_failed',
                    'user':  user_match.group(1) if user_match else '',
                    'src_ip': ip_match.group(1) if ip_match else '',
                    'threat_hint': 'ssh_bruteforce',
                })
            elif 'accepted' in msg:
                user_match = re.search(r'for\s+(\S+)', message, re.I)
                ip_match   = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
                parsed.update({
                    'event': 'ssh_success',
                    'user':  user_match.group(1) if user_match else '',
                    'src_ip': ip_match.group(1) if ip_match else '',
                })
        elif 'sudo' in program.lower():
            cmd_match = re.search(r'COMMAND=(.+)', message)
            parsed.update({
                'event':   'sudo_command',
                'command': cmd_match.group(1).strip() if cmd_match else '',
            })
            if 'not in sudoers' in msg:
                parsed['threat_hint'] = 'privilege_escalation'
    except Exception as e:
        parsed['parse_error'] = str(e)
    return parsed


def parse_windows_ad(message):
    parsed = {}
    try:
        event_map = {
            '4624': ('logon_success', False), '4625': ('logon_failed', True),
            '4634': ('logoff', False),         '4720': ('account_created', True),
            '4740': ('account_lockout', True), '4771': ('kerberos_failed', True),
        }
        event_match = re.search(r'EventID[:\s]+(\d+)', message, re.I)
        if event_match:
            eid = event_match.group(1)
            if eid in event_map:
                event, is_threat = event_map[eid]
                parsed['event_id'] = eid
                parsed['event']    = event
                if is_threat:
                    parsed['threat_hint'] = f'ad_{event}'
        user_match = re.search(r'Account Name[:\s]+(\S+)', message, re.I)
        if user_match:
            parsed['user'] = user_match.group(1)
    except Exception as e:
        parsed['parse_error'] = str(e)
    return parsed


def parse_syslog_message(raw_message, source_ip):
    try:
        raw = raw_message.decode('utf-8', errors='replace').strip()
    except Exception:
        raw = str(raw_message)

    priority, facility, severity = parse_priority(raw)
    msg     = re.sub(r'^<\d+>', '', raw).strip()
    program = ''
    host    = ''

    header_match = re.match(
        r'^(?:(?:\d{4}-\d{2}-\d{2}T[\d:.Z+-]+|\w{3}\s+\d+\s+[\d:]+)\s+)?(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)',
        msg, re.DOTALL
    )
    if header_match:
        host    = header_match.group(1) or ''
        program = header_match.group(2) or ''
        msg     = header_match.group(3) or msg

    info        = detect_source_info(source_ip, program, msg)
    source_type = info.get('source_type', 'unknown')

    parsed = {}
    if source_type == 'opnsense':    parsed = parse_opnsense(msg)
    elif source_type == 'suricata':  parsed = parse_suricata(msg)
    elif source_type == 'linux':     parsed = parse_linux(program, msg)
    elif source_type == 'windows_ad':parsed = parse_windows_ad(msg)

    # Enrichir avec infos VLAN depuis SOURCE_MAP
    if info.get('vlan_id'):
        parsed['vlan_id']   = info['vlan_id']
        parsed['vlan_name'] = info.get('vlan_name', '')

    is_threat   = bool(parsed.get('threat_hint') or parsed.get('is_block'))
    threat_type = parsed.pop('threat_hint', '')

    return {
        'source_ip':      source_ip,
        'source_host':    host,
        'source_type':    source_type,
        'facility':       facility,
        'severity':       severity,
        'priority':       priority,
        'program':        program,
        'message':        msg[:2000],
        'parsed_data':    parsed,
        'is_threat':      is_threat,
        'threat_type':    threat_type,
        'log_timestamp':  datetime.now(timezone.utc).isoformat(),
        'vlan_id':        info.get('vlan_id'),
        'vlan_name':      info.get('vlan_name', ''),
        'org_id':         info.get('org_id'),
    }


# ─── ENVOI À DJANGO ───────────────────────────────────────────────────
send_queue = []
queue_lock = threading.Lock()


def flush_to_django():
    while True:
        time.sleep(2)
        with queue_lock:
            if not send_queue:
                continue
            batch      = send_queue[:50]
            del send_queue[:50]

        try:
            headers = {}
            if django_token:
                headers['Authorization'] = f'Bearer {django_token}'
            r = requests.post(
                f'{DJANGO_URL}/api/alerts/network-logs/',
                json={'logs': batch},
                headers=headers,
                timeout=5,
            )
            if r.ok:
                data = r.json()
                print(f"  📡 {data.get('created',0)} logs envoyés ({data.get('threats',0)} menaces)")
            else:
                print(f"  ⚠ Envoi échoué: {r.status_code}")
        except Exception as e:
            print(f"  ✗ Erreur envoi: {e}")


# ─── SERVEUR SYSLOG UDP ───────────────────────────────────────────────
def start_syslog_server():
    # Auth Django au démarrage
    get_django_token()

    # Thread rechargement SOURCE_MAP
    reload_thread = threading.Thread(target=reload_source_map, daemon=True)
    reload_thread.start()

    # Thread envoi à Django
    flush_thread = threading.Thread(target=flush_to_django, daemon=True)
    flush_thread.start()

    # Attendre que SOURCE_MAP soit chargé
    time.sleep(3)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', SYSLOG_PORT))

    print(f"\n🛡️  Mylo Syslog Server démarré sur UDP:{SYSLOG_PORT}")
    print(f"📡  Django : {DJANGO_URL}")
    print(f"🗺️   {len(SOURCE_MAP)} source(s) configurée(s) — se recharge toutes les {RELOAD_EVERY}s")
    print(f"\n💡 Configurez vos équipements depuis Paramètres → Sources Syslog")
    print(f"   puis redémarrez ce serveur ou attendez {RELOAD_EVERY}s\n")

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            source_ip  = addr[0]
            parsed     = parse_syslog_message(data, source_ip)

            sev_labels = {0:'EMERG',1:'ALERT',2:'CRIT',3:'ERR',4:'WARN',5:'NOTICE',6:'INFO',7:'DEBUG'}
            mark       = '🚨' if parsed['is_threat'] else '📋'
            print(f"  {mark} [{sev_labels.get(parsed['severity'],'?'):6}] "
                  f"{source_ip:15} [{parsed['source_type']:10}] "
                  f"{parsed['message'][:70]}")

            with queue_lock:
                if len(send_queue) < MAX_QUEUE:
                    send_queue.append(parsed)

            # Mettre à jour last_seen de la source
            with map_lock:
                if source_ip in SOURCE_MAP:
                    # Non-bloquant — on le fait en background
                    pass

        except KeyboardInterrupt:
            print("\n⏹  Syslog server arrêté")
            break
        except Exception as e:
            print(f"  ✗ Erreur: {e}")

    sock.close()


if __name__ == '__main__':
    start_syslog_server()