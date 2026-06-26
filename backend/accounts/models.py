from django.db import models
from django.contrib.auth.models import AbstractUser


# ─── ORGANISATION (Tenant) ────────────────────────────────────────────────────
class Organisation(models.Model):
    PLANS = [
        ('free',       'Gratuit'),
        ('pro',        'Professionnel'),
        ('enterprise', 'Entreprise'),
    ]
    SECTORS = [
        ('banking',     'Banque / Finance'),
        ('health',      'Santé'),
        ('industry',    'Industrie'),
        ('government',  'Gouvernement'),
        ('education',   'Éducation'),
        ('telecom',     'Télécommunications'),
        ('retail',      'Commerce / Distribution'),
        ('other',       'Autre'),
    ]

    # Identité
    name        = models.CharField(max_length=200, verbose_name='Nom de l\'organisation')
    slug        = models.SlugField(max_length=100, unique=True,
                    help_text='Identifiant unique (ex: acme-corp)')
    email       = models.EmailField(verbose_name='Email de contact entreprise')
    phone       = models.CharField(max_length=20, blank=True)
    website     = models.URLField(blank=True)
    logo_url    = models.URLField(blank=True)

    # Localisation réseau (Threat Map)
    network_name      = models.CharField(max_length=100, default='Mon Réseau')
    network_latitude  = models.FloatField(default=0.0)
    network_longitude = models.FloatField(default=0.0)
    network_address   = models.CharField(max_length=200, blank=True,
                    help_text='Adresse physique du siège / datacenter')

    # Classification
    sector      = models.CharField(max_length=20, choices=SECTORS, default='other')
    plan        = models.CharField(max_length=20, choices=PLANS, default='free')

    # Statut
    is_active    = models.BooleanField(default=True)
    is_setup_done = models.BooleanField(default=False,
                    help_text='Wizard d\'onboarding complété')

    # Timestamps
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name        = 'Organisation'
        verbose_name_plural = 'Organisations'
        ordering            = ['name']

    def __str__(self):
        return f"{self.name} ({self.plan})"


# ─── UTILISATEUR ──────────────────────────────────────────────────────────────
class User(AbstractUser):

    # ── Niveaux d'habilitation ────────────────────────────────────────────────
    ROLES = [
        ('super_admin',  'Super Administrateur Mylo'),  # équipe Mylo
        ('org_admin',    'Administrateur Organisation'), # configure son org
        ('soc_manager',  'Manager SOC'),                # supervise les analystes
        ('soc_analyst',  'Analyste SOC'),               # analyse et agit
        ('viewer',       'Observateur'),                # lecture seule
    ]

    HABILITATION_LEVELS = [
        (5, 'Niveau 5 — Accès total (Super Admin)'),
        (4, 'Niveau 4 — Administrateur Organisation'),
        (3, 'Niveau 3 — Manager SOC'),
        (2, 'Niveau 2 — Analyste SOC'),
        (1, 'Niveau 1 — Observateur'),
    ]

    # Organisation (tenant)
    organisation = models.ForeignKey(
        Organisation,
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='members',
        verbose_name='Organisation',
    )

    # Rôle et habilitation
    role               = models.CharField(max_length=20, choices=ROLES, default='soc_analyst')
    habilitation_level = models.IntegerField(
        choices=HABILITATION_LEVELS, default=2,
        help_text='Niveau d\'habilitation de sécurité (1=Observateur, 5=Super Admin)'
    )

    # Informations professionnelles
    poste      = models.CharField(max_length=100, blank=True,
                    help_text='Ex: Responsable SOC, Ingénieur réseau, RSSI')
    phone      = models.CharField(max_length=20, blank=True)
    avatar_url = models.URLField(blank=True)

    # TOTP
    totp_secret = models.CharField(max_length=64, blank=True, null=True)
    totp_enabled = models.BooleanField(default=False)
    password_must_change = models.BooleanField(default=False,
                    help_text='Oblige l’utilisateur à changer son mot de passe au prochain login')

    # Sécurité
    last_login_ip    = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    is_locked        = models.BooleanField(default=False,
                    help_text='Compte verrouillé après trop de tentatives')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = 'Utilisateur'
        verbose_name_plural = 'Utilisateurs'

    def __str__(self):
        org = self.organisation.name if self.organisation else 'Sans org'
        return f"{self.username} — {self.get_role_display()} ({org})"

    # ── Permissions par rôle ──────────────────────────────────────────────────
    @property
    def can_view(self):
        return self.habilitation_level >= 1

    @property
    def can_block_ip(self):
        return self.habilitation_level >= 2

    @property
    def can_feedback_river(self):
        return self.habilitation_level >= 2

    @property
    def can_configure_ids(self):
        return self.habilitation_level >= 3

    @property
    def can_manage_users(self):
        return self.habilitation_level >= 4

    @property
    def can_manage_organisations(self):
        return self.habilitation_level >= 5

    @property
    def can_generate_reports(self):
        return self.habilitation_level >= 1

    @property
    def is_super_admin(self):
        return self.role == 'super_admin'

    @property
    def is_org_admin(self):
        return self.role in ('org_admin', 'super_admin')


# ─── AUDIT LOG ────────────────────────────────────────────────────────────────
class AuditLog(models.Model):
    ACTIONS = [
        # Auth
        ('login',              'Connexion'),
        ('logout',             'Déconnexion'),
        ('login_failed',       'Tentative de connexion échouée'),
        # Alertes
        ('alert_view',         'Consultation d\'alerte'),
        ('alert_status_update','Mise à jour statut alerte'),
        ('alert_feedback',     'Feedback River sur alerte'),
        # Wazuh
        ('wazuh_rule_unmapped','Rule ID Wazuh non mappé'),
        # IPs
        ('ip_block',           'Blocage IP'),
        ('ip_unblock',         'Déblocage IP'),
        ('ip_whitelist',       'Whitelisting IP'),
        # Config
        ('settings_update',    'Modification paramètres IDS'),
        ('user_create',        'Création utilisateur'),
        ('user_update',        'Modification utilisateur'),
        ('user_delete',        'Suppression utilisateur'),
        # Rapports
        ('report_generate',    'Génération rapport'),
        ('report_export',      'Export données'),
        # Org
        ('org_update',         'Modification organisation'),
        ('onboarding_complete','Onboarding complété'),
    ]

    # Qui
    user         = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='audit_logs'
    )
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE,
        null=True, blank=True, related_name='audit_logs'
    )
    username     = models.CharField(max_length=150, blank=True,
                    help_text='Sauvegardé en cas de suppression utilisateur')

    # Quoi
    action       = models.CharField(max_length=30, choices=ACTIONS)
    description  = models.TextField(blank=True,
                    help_text='Détails de l\'action')
    object_type  = models.CharField(max_length=50, blank=True,
                    help_text='Type d\'objet concerné (Alert, IP, User...)')
    object_id    = models.CharField(max_length=50, blank=True,
                    help_text='ID de l\'objet concerné')
    object_repr  = models.CharField(max_length=200, blank=True,
                    help_text='Représentation de l\'objet')

    # Contexte technique
    ip_address   = models.GenericIPAddressField(null=True, blank=True,
                    help_text='IP de l\'utilisateur')
    user_agent   = models.CharField(max_length=300, blank=True)
    method       = models.CharField(max_length=10, blank=True,
                    help_text='GET, POST, PATCH...')
    endpoint     = models.CharField(max_length=200, blank=True,
                    help_text='URL appelée')
    status_code  = models.IntegerField(null=True, blank=True)

    # Résultat
    success      = models.BooleanField(default=True)
    extra_data   = models.JSONField(default=dict, blank=True,
                    help_text='Données supplémentaires (avant/après modification)')

    # Timestamp
    timestamp    = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = 'Journal d\'audit'
        verbose_name_plural = 'Journal d\'audit'
        ordering            = ['-timestamp']
        indexes             = [
            models.Index(fields=['organisation', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M}] {self.username} — {self.get_action_display()}"

    @classmethod
    def log(cls, action, user=None, organisation=None, description='',
            object_type='', object_id='', object_repr='',
            ip_address=None, user_agent='', method='', endpoint='',
            status_code=None, success=True, extra_data=None):
        """Méthode utilitaire pour créer un log facilement."""
        return cls.objects.create(
            user=user,
            organisation=organisation or (user.organisation if user else None),
            username=user.username if user else '',
            action=action,
            description=description,
            object_type=object_type,
            object_id=str(object_id),
            object_repr=object_repr,
            ip_address=ip_address,
            user_agent=user_agent[:300] if user_agent else '',
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            success=success,
            extra_data=extra_data or {},
        )