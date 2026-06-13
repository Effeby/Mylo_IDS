"""
Service de découverte d'actifs réseau.
ARP scan (couche 2) + Nmap fingerprinting (OS + ports + services).
"""
import nmap
import threading
from django.utils import timezone


# ─── CLASSIFICATION AUTOMATIQUE ──────────────────────────────────────────────

# Ports → criticité suggérée
PORT_CRITICALITY_MAP = {
    # Ports critiques → criticité 4
    5432: 4,  # PostgreSQL
    3306: 4,  # MySQL
    1433: 4,  # MSSQL
    389:  4,  # LDAP (Active Directory)
    636:  4,  # LDAPS
    88:   4,  # Kerberos (AD)
    445:  4,  # SMB (partage fichiers Windows)
    # Ports hauts → criticité 3
    80:   3,  # HTTP
    443:  3,  # HTTPS
    8000: 3,  # API
    8001: 3,  # Django
    22:   3,  # SSH
    3389: 3,  # RDP
    # Ports standards → criticité 2
    53:   2,  # DNS
    67:   2,  # DHCP
    123:  2,  # NTP
}

# Labels automatiques selon les ports ouverts
def _auto_label(open_ports: list, os_type: str) -> str:
    ports = set(open_ports)
    if ports & {5432, 3306, 1433}:
        return 'Serveur Base de Données'
    if ports & {389, 88, 636}:
        return 'Contrôleur de Domaine (AD)'
    if ports & {80, 443, 8000, 8001}:
        return 'Serveur Web / API'
    if 22 in ports and 'linux' in os_type.lower():
        return 'Serveur Linux'
    if 3389 in ports:
        return 'Poste Windows (RDP)'
    if 67 in ports:
        return 'Serveur DHCP'
    if 53 in ports:
        return 'Serveur DNS'
    return 'Équipement réseau'


def _auto_criticality(open_ports: list) -> int:
    """Détermine la criticité (1-4) selon les ports ouverts."""
    if not open_ports:
        return 2
    max_crit = max(
        PORT_CRITICALITY_MAP.get(p, 1) for p in open_ports
    )
    return max_crit


# ─── ARP SCAN ────────────────────────────────────────────────────────────────

def arp_scan(target_ip: str) -> list:
    """
    Scan ARP actif sur le segment réseau.
    Retourne liste de {'ip': ..., 'mac': ...}
    Nécessite droits admin/root.
    """
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        raise RuntimeError('Scapy non installé : pip install scapy')

    print(f"[ARP] Scan sur {target_ip}...")
    arp    = ARP(pdst=target_ip)
    ether  = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp

    result  = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for _, received in result:
        clients.append({
            'ip':  received.psrc,
            'mac': received.hwsrc,
        })
        print(f"  [ARP] Trouvé : {received.psrc} — {received.hwsrc}")

    print(f"[ARP] {len(clients)} hôtes découverts")
    return clients


# ─── NMAP FINGERPRINTING ─────────────────────────────────────────────────────

def nmap_fingerprint(ip: str) -> dict:
    """
    Fingerprinting Nmap sur une IP.
    Détecte : OS, ports ouverts, services.
    """
    try:
        nm = nmap.PortScanner()
        # -O : détection OS | -sV : version services | --top-ports 20 : ports communs
        nm.scan(ip, arguments='-O -sV --top-ports 20 --host-timeout 10s')

        if ip not in nm.all_hosts():
            return {}

        host = nm[ip]

        # OS
        os_type = ''
        if 'osmatch' in host and host['osmatch']:
            os_type = host['osmatch'][0].get('name', '')

        # Ports et services
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

        return {
            'os_type':    os_type,
            'open_ports': open_ports,
            'services':   services,
        }

    except Exception as e:
        print(f"  [Nmap] Erreur sur {ip}: {e}")
        return {}


# ─── DÉCOUVERTE COMPLÈTE ─────────────────────────────────────────────────────

def discover_and_fingerprint(org, target_cidr: str) -> list:
    """
    Pipeline complet :
    1. ARP scan → liste des hôtes actifs
    2. Nmap fingerprint → OS + ports + services
    3. Classification automatique → criticité + label
    4. Enregistrement en base Django
    """
    from alerts.models import Asset

    # Étape 1 — ARP scan
    clients = arp_scan(target_cidr)
    if not clients:
        print("[Discovery] Aucun hôte trouvé")
        return []

    assets  = []
    results = {}

    # Étape 2 — Nmap fingerprinting (en parallèle)
    def _fingerprint(client):
        ip   = client['ip']
        info = nmap_fingerprint(ip)
        results[ip] = {**client, **info}
        print(f"  [Nmap] {ip} → OS: {info.get('os_type', '?')} | Ports: {info.get('open_ports', [])}")

    threads = [
        threading.Thread(target=_fingerprint, args=(c,))
        for c in clients
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Étape 3 + 4 — Classification + sauvegarde
    for ip, data in results.items():
        open_ports  = data.get('open_ports', [])
        os_type     = data.get('os_type', '')
        services    = data.get('services', {})
        criticality = _auto_criticality(open_ports)
        label       = _auto_label(open_ports, os_type)

        asset, created = Asset.objects.update_or_create(
            organisation=org,
            ip_address=ip,
            defaults={
                'mac_address':  data.get('mac', ''),
                'os_type':      os_type,
                'open_ports':   open_ports,
                'services':     services,
                'label':        label,
                'criticality':  criticality,
                'is_authorized': False,  # À valider manuellement
                'last_seen':    timezone.now(),
            }
        )
        status = '✅ Créé' if created else '🔄 MàJ'
        print(f"  {status} {ip} | {label} | Criticité {criticality}/4 | Autorisé: {asset.is_authorized}")
        assets.append(asset)

    return assets