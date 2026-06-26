"""
Mylo IPS — Classification des alertes Wazuh par rule_id.

Centralise le mapping rule_id Wazuh → classe d'attaque Mylo. Importable
depuis alerts/tasks.py (polling Wazuh) et depuis toute autre vue qui a
besoin de classifier une alerte Wazuh par son rule_id (ex: ingestion
manuelle, vues de debug, futurs connecteurs SIEM).

Pour enrichir le mapping : ajouter l'entrée dans RULE_ID_CLASS_MAP.
Les rule_id rencontrés mais absents de ce mapping sont journalisés dans
AuditLog par alerts/tasks.py (action='wazuh_rule_unmapped') afin de
repérer les rule_id à ajouter ici.
"""

# ─── Classes Mylo couvertes par le mapping Wazuh ──────────────────────────────
BRUTE_FORCE          = 'BruteForce'
PORT_SCAN            = 'PortScan'
MALWARE              = 'Malware'
PRIVILEGE_ESCALATION = 'PrivilegeEscalation'
WEB_ATTACK           = 'WebAttack'
RECONNAISSANCE       = 'Reconnaissance'
NORMAL               = 'Normal'
SUSPICIOUS           = 'Suspicious'

# ─── Mapping rule_id Wazuh → classe Mylo ──────────────────────────────────────
RULE_ID_CLASS_MAP = {
    # BruteForce — échecs d'authentification répétés (SSH, PAM, web, multi-tentatives)
    5551: BRUTE_FORCE,
    5712: BRUTE_FORCE,
    5763: BRUTE_FORCE,
    5710: BRUTE_FORCE,
    5711: BRUTE_FORCE,
    5716: BRUTE_FORCE,
    5720: BRUTE_FORCE,
    5503: BRUTE_FORCE,
    5504: BRUTE_FORCE,

    # PortScan — détection de scan de ports (règles nmap/firewall Wazuh)
    40101: PORT_SCAN,
    40102: PORT_SCAN,
    40111: PORT_SCAN,
    1002:  PORT_SCAN,

    # Malware — détections antivirus / rootcheck / signatures malveillantes
    510:   MALWARE,
    511:   MALWARE,
    512:   MALWARE,
    31103: MALWARE,
    31104: MALWARE,

    # Privilege Escalation — élévation de privilèges (sudo, su, syscheck critique)
    5401: PRIVILEGE_ESCALATION,
    5402: PRIVILEGE_ESCALATION,
    5403: PRIVILEGE_ESCALATION,
    5404: PRIVILEGE_ESCALATION,
    2502: PRIVILEGE_ESCALATION,
    2503: PRIVILEGE_ESCALATION,

    # WebAttack — règles web / modsecurity / injections applicatives
    31101: WEB_ATTACK,
    31102: WEB_ATTACK,
    33101: WEB_ATTACK,
    33102: WEB_ATTACK,
    31151: WEB_ATTACK,

    # Reconnaissance — sondage réseau léger, énumération
    40100: RECONNAISSANCE,
    40110: RECONNAISSANCE,
    19101: RECONNAISSANCE,
}

# Confiance / sévérité par défaut appliquées par classe quand un rule_id
# mappé (ou la classe de repli 'Suspicious') est rencontré.
CLASS_DEFAULTS = {
    BRUTE_FORCE:          {'confidence': 0.90, 'severity': 'HIGH'},
    PORT_SCAN:            {'confidence': 0.80, 'severity': 'MEDIUM'},
    MALWARE:              {'confidence': 0.93, 'severity': 'CRITICAL'},
    PRIVILEGE_ESCALATION: {'confidence': 0.92, 'severity': 'CRITICAL'},
    WEB_ATTACK:           {'confidence': 0.88, 'severity': 'HIGH'},
    RECONNAISSANCE:       {'confidence': 0.75, 'severity': 'MEDIUM'},
    NORMAL:               {'confidence': 0.99, 'severity': 'LOW'},
    SUSPICIOUS:           {'confidence': 0.50, 'severity': 'MEDIUM'},
}


def is_rule_id_mapped(rule_id) -> bool:
    """True si ce rule_id Wazuh a une classe explicitement définie dans le mapping."""
    try:
        return int(rule_id) in RULE_ID_CLASS_MAP
    except (TypeError, ValueError):
        return False


def get_alert_class(rule_id) -> str:
    """
    Classe Mylo associée à un rule_id Wazuh.

    Retourne la classe mappée (BruteForce, PortScan, Malware,
    PrivilegeEscalation, WebAttack, Reconnaissance) si le rule_id est connu,
    sinon 'Normal' par défaut.

    NB : ce 'Normal' par défaut est une classification statique basée
    uniquement sur le rule_id. Pour les rule_id non mappés, alerts/tasks.py
    ne se contente pas de ce défaut : il tente une classification ML
    (XGBoost via /predict) et journalise le rule_id non mappé — voir
    is_rule_id_mapped() pour distinguer un 'Normal' explicite d'un
    rule_id simplement absent du mapping.
    """
    try:
        rule_id = int(rule_id)
    except (TypeError, ValueError):
        return NORMAL
    return RULE_ID_CLASS_MAP.get(rule_id, NORMAL)
