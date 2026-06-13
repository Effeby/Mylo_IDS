from django.contrib import admin
from .models import Alert, Asset, BlacklistedIP, WhitelistedIP, IDSSettings


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display    = ('id', 'organisation', 'attack_type', 'severity', 'src_ip',
                       'dst_ip', 'protocol', 'binary_confidence', 'status', 'detected_at')
    list_filter     = ('organisation', 'attack_type', 'severity', 'status', 'protocol', 'is_attack')
    search_fields   = ('src_ip', 'dst_ip', 'attack_type')
    ordering        = ('-detected_at',)
    readonly_fields = ('detected_at', 'updated_at', 'features')
    fieldsets = (
        ('Tenant',       {'fields': ('organisation',)}),
        ('Détection ML', {'fields': ('attack_type', 'severity', 'is_attack',
                                     'binary_confidence', 'attack_confidence')}),
        ('Asset',        {'fields': ('asset_name', 'asset_criticality', 'asset_multiplier', 'detection_score', 'final_score')}),
        ('Réseau',       {'fields': ('src_ip', 'dst_ip', 'protocol',
                                     'src_bytes', 'dst_bytes', 'duration')}),
        ('Features',     {'fields': ('features',), 'classes': ('collapse',)}),
        ('Statut',       {'fields': ('status', 'action_taken')}),
        ('Timestamps',   {'fields': ('detected_at', 'updated_at'), 'classes': ('collapse',)}),
    )


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'name', 'hostname', 'criticality', 'segment', 'last_seen', 'organisation')
    list_filter  = ('organisation', 'criticality', 'segment')
    search_fields = ('ip_address', 'name', 'hostname', 'segment')
    ordering = ('ip_address',)
    readonly_fields = ('discovered_at', 'updated_at')
    fieldsets = (
        ('Tenant', {'fields': ('organisation',)}),
        ('Identité', {
            'fields': ('ip_address', 'mac_address', 'hostname', 'name', 'segment'),
        }),
        ('Classification', {'fields': ('criticality',)}),
        ('Dates', {'fields': ('last_seen', 'discovered_at', 'updated_at'), 'classes': ('collapse',)}),
    )


@admin.register(BlacklistedIP)
class BlacklistedIPAdmin(admin.ModelAdmin):
    list_display  = ('ip_address', 'organisation', 'reason', 'blocked_by',
                     'alert_count', 'is_active', 'created_at')
    list_filter   = ('organisation', 'blocked_by', 'is_active')
    search_fields = ('ip_address', 'reason')
    ordering      = ('-created_at',)
    actions       = ['debloquer_ips']

    @admin.action(description='Débloquer les IPs sélectionnées')
    def debloquer_ips(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} IP(s) débloquée(s)")


@admin.register(WhitelistedIP)
class WhitelistedIPAdmin(admin.ModelAdmin):
    list_display  = ('ip_address', 'organisation', 'description', 'created_at')
    list_filter   = ('organisation',)
    search_fields = ('ip_address', 'description')
    ordering      = ('-created_at',)


@admin.register(IDSSettings)
class IDSSettingsAdmin(admin.ModelAdmin):
    list_display    = ('organisation', 'updated_at', 'updated_by')
    list_filter     = ('organisation',)
    readonly_fields = ('updated_at', 'updated_by')
    fieldsets = (
        ('Tenant',     {'fields': ('organisation',)}),
        ('Détection',  {'fields': ('binary_threshold', 'confidence_alert')}),
        ('Seuils par classe', {
            'fields': ('threshold_dos', 'threshold_ddos', 'threshold_probe',
                       'threshold_r2l', 'threshold_u2r', 'threshold_bruteforce',
                       'threshold_webattack', 'threshold_botnet', 'threshold_infiltration'),
            'classes': ('collapse',),
        }),
        ('Blocage automatique', {
            'fields': ('auto_block_enabled', 'auto_block_threshold', 'auto_block_duration')
        }),
        ('River', {'fields': ('river_enabled', 'river_learn_threshold')}),
        ('OPNsense IPS', {
            'fields': (
                'opnsense_enabled',
                'opnsense_url',
                'opnsense_api_key',
                'opnsense_api_secret',
            ),
            'classes': ('collapse',),
        }),
        ('Baseline', {
            'fields': ('baseline_validated',),
        }),
        ('Notifications', {
            'fields': (
                'notif_enabled',
                'notif_min_severity',
                # Telegram
                'notif_telegram_enabled',
                'notif_telegram_token',
                'notif_telegram_chat',
                # Email
                'notif_email',
                'notif_email_enabled',
                #'notif_email_address',
                'notif_email_min_severity',
                # Autres
                'notif_webhook_url',
            ),
            'classes': ('collapse',),
        }),
        ('Meta', {'fields': ('updated_at', 'updated_by'), 'classes': ('collapse',)}),
    )