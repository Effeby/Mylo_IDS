from django.db import models

class Alert(models.Model):
    SEVERITIES = [
        ('CRITICAL', 'Critical'),
        ('HIGH',     'High'),
        ('MEDIUM',   'Medium'),
        ('LOW',      'Low'),
    ]
    # 9 classes Mylo
    ATTACK_TYPES = [
        ('Normal',      'Normal'),
        ('DoS',         'DoS'),
        ('DDoS',        'DDoS'),
        ('Probe',       'Probe'),
        ('R2L',         'R2L'),
        ('U2R',         'U2R'),
        ('BruteForce',  'BruteForce'),
        ('WebAttack',   'WebAttack'),
        ('Botnet',      'Botnet'),
        ('Infiltration','Infiltration'),
    ]
    STATUSES = [
        ('new',           'Nouvelle'),
        ('investigating', 'En cours'),
        ('resolved',      'Résolue'),
        ('false_positive','Faux positif'),
    ]

    # Détection ML
    attack_type        = models.CharField(max_length=20, choices=ATTACK_TYPES)
    severity           = models.CharField(max_length=20, choices=SEVERITIES)
    binary_confidence  = models.FloatField()
    attack_confidence  = models.FloatField()
    is_attack          = models.BooleanField(default=True)

    # Réseau
    src_ip    = models.GenericIPAddressField(null=True, blank=True)
    dst_ip    = models.GenericIPAddressField(null=True, blank=True)
    protocol  = models.CharField(max_length=10, blank=True)
    src_bytes = models.FloatField(default=0)
    dst_bytes = models.FloatField(default=0)
    duration  = models.FloatField(default=0)

    # Features utilisées par le modèle (JSON)
    features  = models.JSONField(default=dict)

    # Statut
    status       = models.CharField(max_length=20, choices=STATUSES, default='new')
    action_taken = models.CharField(max_length=100, blank=True)

    # Timestamps
    detected_at = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-detected_at']

    def __str__(self):
        return f"[{self.severity}] {self.attack_type} — {self.src_ip} → {self.dst_ip}"


class BlacklistedIP(models.Model):
    ip_address  = models.GenericIPAddressField(unique=True)
    reason      = models.CharField(max_length=200, blank=True)
    blocked_by  = models.CharField(max_length=50, default='manual')
    alert_count = models.IntegerField(default=0)
    created_at  = models.DateTimeField(auto_now_add=True)
    expires_at  = models.DateTimeField(null=True, blank=True)
    is_active   = models.BooleanField(default=True)

    def __str__(self):
        return f"🔴 {self.ip_address} — {self.reason}"


class WhitelistedIP(models.Model):
    ip_address  = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=200, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"🟢 {self.ip_address} — {self.description}"
    

class IDSSettings(models.Model):
    """
    Paramètres IDS — singleton (une seule ligne en base).
    Modifiables depuis le dashboard sans redémarrer Django.
    """
    # ── Détection ────────────────────────────────────────────────────
    binary_threshold   = models.FloatField(default=0.50,
        help_text="Seuil binaire (prob. min pour déclarer une attaque)")
    confidence_alert   = models.FloatField(default=0.70,
        help_text="Confiance min pour alerte 'Nouvelle' (sinon 'À vérifier')")

    # ── Thresholds par classe ─────────────────────────────────────────
    threshold_dos          = models.FloatField(default=0.65)
    threshold_ddos         = models.FloatField(default=0.60)
    threshold_probe        = models.FloatField(default=0.55)
    threshold_r2l          = models.FloatField(default=0.25)
    threshold_u2r          = models.FloatField(default=0.15)
    threshold_bruteforce   = models.FloatField(default=0.35)
    threshold_webattack    = models.FloatField(default=0.35)
    threshold_botnet       = models.FloatField(default=0.25)
    threshold_infiltration = models.FloatField(default=0.20)

    # ── Blocage automatique ───────────────────────────────────────────
    auto_block_enabled   = models.BooleanField(default=False,
        help_text="Bloquer automatiquement les IP suspectes")
    auto_block_threshold = models.FloatField(default=0.85,
        help_text="Score au-dessus duquel on bloque automatiquement")
    auto_block_duration  = models.IntegerField(default=3600,
        help_text="Durée du blocage automatique en secondes (3600 = 1h)")

    # ── River / apprentissage en ligne ────────────────────────────────
    river_enabled        = models.BooleanField(default=True,
        help_text="Activer l'apprentissage en ligne River")
    river_learn_threshold = models.FloatField(default=0.70,
        help_text="Confiance min pour que River apprenne automatiquement")

    # ── Notifications ─────────────────────────────────────────────────
    notif_enabled        = models.BooleanField(default=False)
    notif_telegram_token = models.CharField(max_length=200, blank=True)
    notif_telegram_chat  = models.CharField(max_length=100, blank=True)
    notif_email          = models.EmailField(blank=True)
    notif_webhook_url    = models.URLField(blank=True)
    notif_min_severity   = models.CharField(max_length=10, default='HIGH',
        choices=[('CRITICAL','Critical'),('HIGH','High'),('MEDIUM','Medium')])

    # ── Localisation du réseau surveillé ─────────────────────────────
    network_name      = models.CharField(max_length=100, default='Mon Réseau',
        help_text="Nom du réseau surveillé (affiché sur la Threat Map)")
    network_latitude  = models.FloatField(default=0.0,
        help_text="Latitude du siège / datacenter")
    network_longitude = models.FloatField(default=0.0,
        help_text="Longitude du siège / datacenter")

    # ── Meta ──────────────────────────────────────────────────────────
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, blank=True)

    class Meta:
        verbose_name        = 'IDS Settings'
        verbose_name_plural = 'IDS Settings'

    def __str__(self):
        return f"IDS Settings (mis à jour {self.updated_at})"

    @classmethod
    def get(cls):
        """Toujours retourner la seule instance (singleton)."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj