
from django.db import models
import math
 
 
class Alert(models.Model):
    SEVERITIES = [
        ('CRITICAL', 'Critical'),
        ('HIGH',     'High'),
        ('MEDIUM',   'Medium'),
        ('LOW',      'Low'),
    ]
    ATTACK_TYPES = [
        ('Normal',              'Normal'),
        ('DoS',                 'DoS'),
        ('DDoS',                'DDoS'),
        ('Probe',               'Probe'),
        ('R2L',                 'R2L'),
        ('U2R',                 'U2R'),
        ('BruteForce',          'BruteForce'),
        ('WebAttack',           'WebAttack'),
        ('Botnet',              'Botnet'),
        ('Infiltration',        'Infiltration'),
        # Classes issues du mapping rule_id Wazuh (alerts/wazuh_rules.py)
        ('PortScan',            'Port Scan'),
        ('Malware',             'Malware'),
        ('PrivilegeEscalation', 'Privilege Escalation'),
        ('Reconnaissance',      'Reconnaissance'),
        ('Suspicious',          'Suspicious'),
    ]
    STATUSES = [
        ('new',           'Nouvelle'),
        ('investigating', 'En cours'),
        ('resolved',      'Résolue'),
        ('false_positive','Faux positif'),
        ('confirmed',     'Confirmée'),
        ('under_review',  'À vérifier'),
        ('ignored',       'Ignorée'),
        ('normal',        'Normal'),
    ]
 
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='alerts',
        db_index=True,
    )
 
    attack_type        = models.CharField(max_length=20, choices=ATTACK_TYPES)
    severity           = models.CharField(max_length=20, choices=SEVERITIES)
    binary_confidence  = models.FloatField()
    attack_confidence  = models.FloatField()
    is_attack          = models.BooleanField(default=True)
 
    src_ip    = models.GenericIPAddressField(null=True, blank=True)
    dst_ip    = models.GenericIPAddressField(null=True, blank=True)
    protocol  = models.CharField(max_length=10, blank=True)
    src_bytes = models.FloatField(default=0)
    dst_bytes = models.FloatField(default=0)
    duration  = models.FloatField(default=0)
 
    features  = models.JSONField(default=dict)
 
    detection_score   = models.FloatField(default=0.0)
    final_score       = models.FloatField(default=0.0)
    asset_name        = models.CharField(max_length=150, blank=True)
    asset_criticality = models.CharField(max_length=10, choices=[
        ('PUBLIC', 'Public'),
        ('INTERNAL', 'Interne'),
        ('CRITICAL', 'Critique'),
    ], default='INTERNAL')
    asset_multiplier  = models.FloatField(default=1.0)
 
    status       = models.CharField(max_length=20, choices=STATUSES, default='new')
    action_taken = models.CharField(max_length=100, blank=True)
    # Source of the alert (e.g. 'scapy', 'wazuh') — helps identify origin
    source = models.CharField(max_length=20, default='scapy')
 
    detected_at = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)
 
    class Meta:
        ordering = ['-detected_at']
        indexes  = [
            models.Index(fields=['organisation', '-detected_at']),
            models.Index(fields=['organisation', 'is_attack']),
        ]
 
    def __str__(self):
        asset_label = f" {self.asset_name}" if self.asset_name else ''
        return f"[{self.severity}] {self.attack_type} — {self.src_ip} → {self.dst_ip}{asset_label}"
 
 
class Asset(models.Model):
 
    CRITICALITY_CHOICES = [
        (4, 'Critique'),
        (3, 'Haute'),
        (2, 'Moyenne'),
        (1, 'Basse'),
    ]
 
    CRITICALITY_MULTIPLIER = {
        4: 2.0,
        3: 1.5,
        2: 1.0,
        1: 0.7,
    }
 
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        related_name='assets',
        null=True,
        blank=True,
    )
    ip_address    = models.GenericIPAddressField()
    mac_address   = models.CharField(max_length=17, blank=True)
    hostname      = models.CharField(max_length=255, blank=True)
    name          = models.CharField(max_length=255, blank=True)
    label         = models.CharField(max_length=200, blank=True)
    segment       = models.CharField(max_length=100, blank=True)
    vlan_id       = models.IntegerField(null=True, blank=True)
    os_type       = models.CharField(max_length=200, blank=True)
    open_ports    = models.JSONField(default=list, blank=True)
    services      = models.JSONField(default=dict, blank=True)
    description   = models.TextField(blank=True)
    is_static_ip  = models.BooleanField(default=True)
    is_authorized = models.BooleanField(default=False)
    criticality   = models.IntegerField(
        choices=CRITICALITY_CHOICES,
        default=2
    )
 
    last_seen     = models.DateTimeField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)
 
    class Meta:
        unique_together = ('organisation', 'ip_address')
        ordering = ['-criticality', 'ip_address']
 
    def __str__(self):
        return f"{self.ip_address} — {self.name or self.hostname or 'Inconnu'}"
 
    @property
    def multiplier(self):
        return self.CRITICALITY_MULTIPLIER.get(self.criticality, 1.0)
 
    @property
    def criticality_label(self):
        return dict(self.CRITICALITY_CHOICES).get(self.criticality, 'Moyenne')
 
    @classmethod
    def discover_from_traffic(cls, org, lookback_hours=24):
        from django.utils import timezone
        from datetime import timedelta
        since = timezone.now() - timedelta(hours=lookback_hours)
        alerts = Alert.objects.filter(
            organisation=org,
            detected_at__gte=since
        ).values('src_ip', 'dst_ip').distinct()
 
        assets = []
        for a in alerts:
            for ip in [a['src_ip'], a['dst_ip']]:
                if not ip:
                    continue
                if not (
                    ip.startswith('192.168.') or
                    ip.startswith('10.') or
                    ip.startswith('172.16.') or
                    ip.startswith('172.17.') or
                    ip.startswith('172.31.')
                ):
                    continue
                asset, _ = cls.objects.get_or_create(
                    organisation=org,
                    ip_address=ip,
                    defaults={'criticality': 2}
                )
                assets.append(asset)
        return assets
 
 
class BlacklistedIP(models.Model):
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='blacklisted_ips',
        db_index=True,
    )
    ip_address  = models.GenericIPAddressField()
    reason      = models.CharField(max_length=200, blank=True)
    blocked_by  = models.CharField(max_length=50, default='manual')
    alert_count = models.IntegerField(default=0)
    created_at  = models.DateTimeField(auto_now_add=True)
    expires_at  = models.DateTimeField(null=True, blank=True)
    is_active   = models.BooleanField(default=True)
 
    class Meta:
        unique_together = ('organisation', 'ip_address')
 
    def __str__(self):
        return f"🔴 {self.ip_address} — {self.reason}"
 
 
class WhitelistedIP(models.Model):
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='whitelisted_ips',
        db_index=True,
    )
    ip_address  = models.GenericIPAddressField()
    description = models.CharField(max_length=200, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)
 
    class Meta:
        unique_together = ('organisation', 'ip_address')
 
    def __str__(self):
        return f"🟢 {self.ip_address} — {self.description}"
 
 
class IDSSettings(models.Model):
    organisation = models.OneToOneField(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='ids_settings',
    )
 
    binary_threshold   = models.FloatField(default=0.50)
    confidence_alert   = models.FloatField(default=0.70)
 
    threshold_dos          = models.FloatField(default=0.65)
    threshold_ddos         = models.FloatField(default=0.60)
    threshold_probe        = models.FloatField(default=0.55)
    threshold_r2l          = models.FloatField(default=0.25)
    threshold_u2r          = models.FloatField(default=0.15)
    threshold_bruteforce   = models.FloatField(default=0.35)
    threshold_webattack    = models.FloatField(default=0.35)
    threshold_botnet       = models.FloatField(default=0.25)
    threshold_infiltration = models.FloatField(default=0.20)
 
    auto_block_enabled   = models.BooleanField(default=False)
    auto_block_threshold = models.FloatField(default=0.85)
    auto_block_duration  = models.IntegerField(default=3600)
 
    river_enabled         = models.BooleanField(default=True)
    river_learn_threshold = models.FloatField(default=0.70)
 
    notif_enabled        = models.BooleanField(default=False)
    notif_telegram_token = models.CharField(max_length=200, blank=True)
    notif_telegram_chat  = models.CharField(max_length=100, blank=True)
    notif_email          = models.EmailField(blank=True)
    notif_webhook_url    = models.URLField(blank=True)
    notif_min_severity   = models.CharField(max_length=10, default='HIGH',
        choices=[('CRITICAL','Critical'),('HIGH','High'),('MEDIUM','Medium')])
 
    notif_email_enabled  = models.BooleanField(default=False)
    notif_email_address  = models.EmailField(blank=True, default='')
    notif_email_min_severity = models.CharField(
        max_length=10, default='HIGH',
        choices=[('CRITICAL','Critical'),('HIGH','High'),('MEDIUM','Medium')]
    )
 
    notif_telegram_enabled = models.BooleanField(default=False)
 
    network_name      = models.CharField(max_length=100, default='Mon Réseau')
    network_latitude  = models.FloatField(default=0.0)
    network_longitude = models.FloatField(default=0.0)
 
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, blank=True)
 
    opnsense_url        = models.URLField(blank=True, default='https://172.16.1.1')
    opnsense_api_key    = models.CharField(max_length=200, blank=True)
    opnsense_api_secret = models.CharField(max_length=200, blank=True)
    opnsense_enabled    = models.BooleanField(default=False)
 
    baseline_validated  = models.BooleanField(default=False)
 
    class Meta:
        verbose_name        = 'IDS Settings'
        verbose_name_plural = 'IDS Settings'
 
    def __str__(self):
        org = self.organisation.name if self.organisation else 'Global'
        return f"IDS Settings — {org}"
 
    @classmethod
    def get(cls, organisation=None):
        obj, _ = cls.objects.get_or_create(organisation=organisation)
        return obj
 
 
class NetworkLog(models.Model):
    SOURCE_TYPES = [
        ('opnsense',   'OPNsense Firewall'),
        ('suricata',   'Suricata IDS'),
        ('linux',      'Linux/Ubuntu'),
        ('windows_ad', 'Windows Server / AD'),
        ('switch',     'Switch réseau'),
        ('unknown',    'Source inconnue'),
    ]
 
    SEVERITIES = [
        (0, 'Emergency'), (1, 'Alert'),  (2, 'Critical'),
        (3, 'Error'),     (4, 'Warning'),(5, 'Notice'),
        (6, 'Info'),      (7, 'Debug'),
    ]
 
    FACILITIES = [
        (0,  'kern'),    (1,  'user'),   (2,  'mail'),
        (3,  'daemon'),  (4,  'auth'),   (5,  'syslog'),
        (6,  'lpr'),     (7,  'news'),   (8,  'uucp'),
        (9,  'cron'),    (10, 'authpriv'),(11, 'ftp'),
        (16, 'local0'),  (17, 'local1'), (18, 'local2'),
        (19, 'local3'),  (20, 'local4'), (21, 'local5'),
        (22, 'local6'),  (23, 'local7'),
    ]
 
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='network_logs',
        db_index=True,
    )
 
    source_ip   = models.GenericIPAddressField()
    source_host = models.CharField(max_length=255, blank=True)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES, default='unknown')
    vlan_id     = models.IntegerField(null=True, blank=True)
    vlan_name   = models.CharField(max_length=100, blank=True)
 
    facility    = models.IntegerField(choices=FACILITIES, default=16)
    severity    = models.IntegerField(choices=SEVERITIES, default=6)
    priority    = models.IntegerField(default=0)
 
    program     = models.CharField(max_length=100, blank=True)
    message     = models.TextField()
    parsed_data = models.JSONField(default=dict, blank=True)
 
    is_threat   = models.BooleanField(default=False)
    threat_type = models.CharField(max_length=100, blank=True)
    reviewed    = models.BooleanField(default=False)
 
    log_timestamp = models.DateTimeField()
    received_at   = models.DateTimeField(auto_now_add=True)
 
    class Meta:
        ordering = ['-log_timestamp']
        indexes  = [
            models.Index(fields=['organisation', '-log_timestamp']),
            models.Index(fields=['organisation', 'source_type']),
            models.Index(fields=['organisation', 'is_threat']),
            models.Index(fields=['source_ip']),
        ]
 
    def __str__(self):
        return f"[{self.get_source_type_display()}] {self.source_ip} — {self.message[:60]}"
 
    @property
    def severity_label(self):
        labels = {0:'Emergency',1:'Alert',2:'Critical',3:'Error',
                  4:'Warning',5:'Notice',6:'Info',7:'Debug'}
        return labels.get(self.severity, 'Unknown')
 
    @property
    def severity_color(self):
        colors = {0:'#EF4444',1:'#EF4444',2:'#EF4444',3:'#F97316',
                  4:'#EAB308',5:'#3B82F6',6:'#94A3B8',7:'#475569'}
        return colors.get(self.severity, '#94A3B8')
 
 
class SyslogSource(models.Model):
    SOURCE_TYPES = [
        ('opnsense',   'OPNsense Firewall'),
        ('suricata',   'Suricata IDS'),
        ('linux',      'Linux / Ubuntu'),
        ('windows_ad', 'Windows Server / AD'),
        ('switch',     'Switch réseau'),
        ('router',     'Routeur'),
        ('other',      'Autre'),
    ]
 
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        related_name='syslog_sources',
    )
 
    name        = models.CharField(max_length=100)
    ip_address  = models.GenericIPAddressField()
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES, default='other')
    description = models.CharField(max_length=200, blank=True)
 
    vlan_id     = models.IntegerField(null=True, blank=True)
    vlan_name   = models.CharField(max_length=100, blank=True)
 
    is_active   = models.BooleanField(default=True)
 
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)
    last_seen   = models.DateTimeField(null=True, blank=True)
    log_count   = models.IntegerField(default=0)
 
    class Meta:
        unique_together = ('organisation', 'ip_address')
        ordering        = ['name']
 
    def __str__(self):
        return f"{self.name} ({self.ip_address}) — {self.get_source_type_display()}"
 
 
class IPBaseline(models.Model):
    """
    Profil comportemental d'une IP observée sur le réseau.
    Mis à jour en temps réel à chaque flux analysé via l'algorithme de Welford.
 
    FIX 1 — Welford exact : utilisation de m2_bytes et m2_duration comme
             accumulateurs de variance, conformément à l'algorithme original
             (Welford, 1962). L'ancienne formule recalculait std**2 depuis
             lui-même, introduisant une dérive d'arrondi cumulative.
 
    FIX 2 — Ports typiques pondérés : typical_ports est maintenant un dict
             {port: count} au lieu d'une liste. Un port n'est considéré
             "typique" que s'il représente >= 2% des flux observés, évitant
             les faux négatifs sur la détection de ports inhabituels.
 
    FIX 3 — Décroissance du score ralentie : le facteur passe de 0.90 à 0.98
             par flux normal, empêchant une IP suspecte de se "réhabiliter"
             trop rapidement entre deux séquences d'attaques.
    """
 
    # ── Tenant ────────────────────────────────────────────────────────
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        related_name='ip_baselines',
        db_index=True,
    )
 
    # ── Identification ────────────────────────────────────────────────
    ip_address  = models.GenericIPAddressField(db_index=True)
    is_internal = models.BooleanField(default=True,
        help_text="IP interne (réseau surveillé) ou externe (internet)")
 
    # ── Statistiques trafic (moyennes glissantes — Welford) ───────────
    avg_bytes_per_flow   = models.FloatField(default=0.0)
    avg_duration         = models.FloatField(default=0.0)
    avg_requests_per_min = models.FloatField(default=0.0)
    avg_src_bytes        = models.FloatField(default=0.0)
    avg_dst_bytes        = models.FloatField(default=0.0)
 
    # ── Accumulateurs de variance Welford (FIX 1) ─────────────────────
    # M2 = somme des carrés des écarts à la moyenne courante
    # std = sqrt(M2 / n)  →  calcul exact, sans dérive d'arrondi
    m2_bytes    = models.FloatField(default=0.0,
        help_text="Accumulateur Welford pour la variance des bytes")
    m2_duration = models.FloatField(default=0.0,
        help_text="Accumulateur Welford pour la variance des durées")
 
    # ── Écarts-types dérivés (lecture seule, recalculés à chaque flux) ─
    std_bytes_per_flow   = models.FloatField(default=0.0)
    std_requests_per_min = models.FloatField(default=0.0)
    std_duration         = models.FloatField(default=0.0)
 
    # ── Comportements typiques ────────────────────────────────────────
    # FIX 2 : typical_ports est maintenant un dict {str(port): count}
    # Ex: {"80": 120, "443": 95, "22": 3}
    # Un port est "typique" si count/total_flows >= 0.02
    typical_ports     = models.JSONField(default=dict,
        help_text="Fréquence des ports destination : {port: count}")
    typical_protocols = models.JSONField(default=dict,
        help_text="Répartition protocoles: {'TCP': 0.8, 'UDP': 0.2}")
    typical_dst_ips   = models.JSONField(default=list,
        help_text="IPs destination habituelles (top 10)")
 
    # ── Compteurs ─────────────────────────────────────────────────────
    total_flows          = models.IntegerField(default=0)
    total_bytes          = models.BigIntegerField(default=0)
    attack_count         = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)
 
    # ── Score d'anomalie ──────────────────────────────────────────────
    anomaly_score     = models.FloatField(default=0.0,
        help_text="Score actuel (0=normal, >3=suspect, >5=critique)")
    last_anomaly_type = models.CharField(max_length=100, blank=True)
    is_suspicious     = models.BooleanField(default=False)
 
    # ── Phase baseline ────────────────────────────────────────────────
    baseline_established   = models.BooleanField(default=False)
    min_flows_for_baseline = 20
 
    # ── Timestamps ────────────────────────────────────────────────────
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen  = models.DateTimeField(auto_now=True)
 
    class Meta:
        unique_together = ('organisation', 'ip_address')
        ordering        = ['-anomaly_score', '-last_seen']
        indexes = [
            models.Index(fields=['organisation', 'is_suspicious']),
            models.Index(fields=['organisation', '-anomaly_score']),
        ]
 
    def __str__(self):
        return (f"{self.ip_address} "
                f"(org={self.organisation_id}, "
                f"flows={self.total_flows}, "
                f"score={self.anomaly_score:.2f})")
 
    # ─────────────────────────────────────────────────────────────────
    def update_baseline(self, flow_data: dict) -> dict:
        """
        Met à jour la baseline avec un nouveau flux et retourne
        le score d'anomalie + la liste des anomalies détectées.
        """
        src_bytes   = float(flow_data.get('src_bytes', 0))
        dst_bytes   = float(flow_data.get('dst_bytes', 0))
        duration    = float(flow_data.get('duration', 0))
        dst_port    = int(flow_data.get('dst_port', 0))
        protocol    = str(flow_data.get('protocol', 'TCP'))
        dst_ip      = str(flow_data.get('dst_ip', ''))
        total_bytes = src_bytes + dst_bytes
 
        anomalies     = []
        anomaly_score = 0.0
 
        # ── Phase apprentissage (warm-up) ─────────────────────────────
        if self.total_flows < self.min_flows_for_baseline:
            self._update_stats(src_bytes, dst_bytes, duration, dst_port, protocol, dst_ip)
            self.total_flows += 1
            self.total_bytes += int(total_bytes)
            if self.total_flows >= self.min_flows_for_baseline:
                self.baseline_established = True
            return {'anomaly_score': 0.0, 'anomalies': [], 'learning': True}
 
        # ── 1. Volume de bytes anormal (Z-score Welford exact) ────────
        if self.std_bytes_per_flow > 0:
            z_bytes = abs(total_bytes - self.avg_bytes_per_flow) / (self.std_bytes_per_flow + 1)
            if z_bytes > 3:
                factor = total_bytes / max(self.avg_bytes_per_flow, 1)
                anomalies.append({
                    'type':     'volume_anormal',
                    'detail':   f"{factor:.1f}x le volume habituel",
                    'z_score':  round(z_bytes, 2),
                    'severity': 'CRITICAL' if z_bytes > 6 else 'HIGH' if z_bytes > 4 else 'MEDIUM',
                })
                anomaly_score += min(z_bytes, 10)
 
        # ── 2. Port inhabituel (FIX 2 — seuil fréquence 2%) ──────────
        if dst_port > 0:
            ports       = dict(self.typical_ports) if self.typical_ports else {}
            total_flows = max(self.total_flows, 1)
            port_ratio  = ports.get(str(dst_port), 0) / total_flows
 
            if port_ratio < 0.02:
                label = "jamais observé" if str(dst_port) not in ports else f"rare ({port_ratio*100:.1f}% des flux)"
                anomalies.append({
                    'type':     'port_inhabituel',
                    'detail':   f"Port {dst_port} {label} pour cette IP",
                    'z_score':  2.0,
                    'severity': 'MEDIUM',
                })
                anomaly_score += 2.0
 
        # ── 3. Protocole inhabituel ───────────────────────────────────
        if protocol and self.typical_protocols:
            proto_ratio = self.typical_protocols.get(protocol, 0)
            if proto_ratio < 0.05:
                anomalies.append({
                    'type':     'protocole_inhabituel',
                    'detail':   f"Protocole {protocol} rare ({proto_ratio*100:.0f}% du trafic habituel)",
                    'z_score':  1.5,
                    'severity': 'LOW',
                })
                anomaly_score += 1.5
 
        # ── 4. Nouvelle destination jamais vue ────────────────────────
        if dst_ip and self.typical_dst_ips and dst_ip not in self.typical_dst_ips:
            anomalies.append({
                'type':     'destination_inconnue',
                'detail':   f"Connexion vers {dst_ip} jamais observée",
                'z_score':  1.0,
                'severity': 'LOW',
            })
            anomaly_score += 1.0
 
        # ── 5. Durée anormale (Z-score Welford exact) ─────────────────
        if self.std_duration > 0:
            z_dur = abs(duration - self.avg_duration) / (self.std_duration + 0.001)
            if z_dur > 4:
                anomalies.append({
                    'type':     'duree_anormale',
                    'detail':   f"Durée {duration:.2f}s vs moyenne {self.avg_duration:.2f}s",
                    'z_score':  round(z_dur, 2),
                    'severity': 'MEDIUM',
                })
                anomaly_score += min(z_dur / 2, 3)
 
        # ── Mise à jour des statistiques ──────────────────────────────
        self._update_stats(src_bytes, dst_bytes, duration, dst_port, protocol, dst_ip)
        self.total_flows += 1
        self.total_bytes += int(total_bytes)
 
        # ── Mise à jour du score d'anomalie ───────────────────────────
        if not anomalies:
            # FIX 3 — décroissance lente : 0.98 au lieu de 0.90
            # Évite qu'une IP suspecte se "réhabilite" après seulement
            # quelques flux normaux entre deux séquences d'attaques.
            self.anomaly_score = max(0.0, self.anomaly_score * 0.98)
        else:
            self.anomaly_score = min(10.0, self.anomaly_score * 0.7 + anomaly_score)
            self.last_anomaly_type = anomalies[0]['type']
 
        self.is_suspicious = self.anomaly_score > 3.0
 
        return {
            'anomaly_score': round(self.anomaly_score, 2),
            'anomalies':     anomalies,
            'learning':      False,
            'is_suspicious': self.is_suspicious,
        }
 
    # ─────────────────────────────────────────────────────────────────
    def _update_stats(self, src_bytes, dst_bytes, duration, dst_port, protocol, dst_ip):
        """
        Mise à jour incrémentale des moyennes et variances.
 
        Algorithme de Welford (1962) — version exacte :
            n       = total_flows + 1  (après ce flux)
            delta   = valeur - ancienne_moyenne
            moyenne = ancienne_moyenne + delta / n
            delta2  = valeur - nouvelle_moyenne
            M2      = M2 + delta * delta2        ← accumulateur exact
            std     = sqrt(M2 / n)
        """
        total_bytes = src_bytes + dst_bytes
        n = self.total_flows + 1  # n après ce flux
 
        # ── Bytes per flow (Welford exact) ────────────────────────────
        delta_b             = total_bytes - self.avg_bytes_per_flow
        self.avg_bytes_per_flow += delta_b / n
        delta2_b            = total_bytes - self.avg_bytes_per_flow
        self.m2_bytes      += delta_b * delta2_b
        self.std_bytes_per_flow = math.sqrt(self.m2_bytes / n) if n > 1 else 0.0
 
        # ── Duration (Welford exact) ──────────────────────────────────
        delta_d             = duration - self.avg_duration
        self.avg_duration  += delta_d / n
        delta2_d            = duration - self.avg_duration
        self.m2_duration   += delta_d * delta2_d
        self.std_duration   = math.sqrt(self.m2_duration / n) if n > 1 else 0.0
 
        # ── Src / Dst bytes (moyennes simples) ────────────────────────
        self.avg_src_bytes += (src_bytes - self.avg_src_bytes) / n
        self.avg_dst_bytes += (dst_bytes - self.avg_dst_bytes) / n
 
        # ── Ports typiques — dict fréquence {port: count} (FIX 2) ─────
        ports = dict(self.typical_ports) if isinstance(self.typical_ports, dict) else {}
        if dst_port > 0:
            ports[str(dst_port)] = ports.get(str(dst_port), 0) + 1
            # Garder les 20 ports les plus fréquents
            if len(ports) > 20:
                ports = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:20])
        self.typical_ports = ports
 
        # ── Protocoles typiques (ratios) ──────────────────────────────
        protos = dict(self.typical_protocols) if self.typical_protocols else {}
        total  = sum(protos.values()) + 1
        for p in protos:
            protos[p] = protos[p] / total
        protos[protocol] = protos.get(protocol, 0) + 1 / total
        self.typical_protocols = protos
 
        # ── IPs destination typiques (top 10) ─────────────────────────
        dsts = list(self.typical_dst_ips) if self.typical_dst_ips else []
        if dst_ip and dst_ip not in dsts:
            dsts.append(dst_ip)
            if len(dsts) > 10:
                dsts = dsts[-10:]
        self.typical_dst_ips = dsts
 
 
class AlertCorrelation(models.Model):
    SCENARIO_TYPES = [
        ('recon_exploit',     'Reconnaissance → Exploitation'),
        ('recon_dos',         'Reconnaissance → DoS'),
        ('brute_exploit',     'BruteForce → Exploitation'),
        ('multi_vector',      'Attaque multi-vecteurs'),
        ('persistence',       'Tentative de persistance'),
        ('lateral_movement',  'Mouvement latéral'),
        ('data_exfiltration', 'Exfiltration de données'),
        ('coordinated',       'Attaque coordonnée'),
        ('unknown',           'Scénario inconnu'),
    ]
 
    RISK_LEVELS = [
        ('LOW',      'Faible'),
        ('MEDIUM',   'Moyen'),
        ('HIGH',     'Élevé'),
        ('CRITICAL', 'Critique'),
    ]
 
    organisation = models.ForeignKey(
        'accounts.Organisation',
        on_delete=models.CASCADE,
        related_name='correlations',
        db_index=True,
    )
 
    src_ip        = models.GenericIPAddressField(db_index=True)
    scenario_type = models.CharField(max_length=30, choices=SCENARIO_TYPES, default='unknown')
    risk_level    = models.CharField(max_length=10, choices=RISK_LEVELS, default='MEDIUM')
 
    alerts        = models.ManyToManyField('Alert', related_name='correlations', blank=True)
    alert_count   = models.IntegerField(default=0)
    attack_types  = models.JSONField(default=list)
 
    description          = models.TextField()
    next_step_prediction = models.CharField(max_length=100, blank=True)
    confidence           = models.FloatField(default=0.0)
    recommended_action   = models.CharField(max_length=200, blank=True)
 
    is_active   = models.BooleanField(default=True)
    is_notified = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
 
    first_alert_at = models.DateTimeField()
    last_alert_at  = models.DateTimeField(auto_now=True)
    created_at     = models.DateTimeField(auto_now_add=True)
 
    class Meta:
        ordering = ['-last_alert_at']
        indexes  = [
            models.Index(fields=['organisation', 'is_active']),
            models.Index(fields=['organisation', 'src_ip']),
            models.Index(fields=['organisation', '-last_alert_at']),
        ]
 
    def __str__(self):
        return (f"[{self.risk_level}] {self.get_scenario_type_display()} "
                f"— {self.src_ip} ({self.alert_count} alertes)")
 
    def duration_seconds(self):
        return (self.last_alert_at - self.first_alert_at).total_seconds()
