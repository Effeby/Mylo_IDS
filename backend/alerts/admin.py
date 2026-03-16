from django.contrib import admin
from .models import Alert, BlacklistedIP, WhitelistedIP, IDSSettings


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display    = ('id', 'attack_type', 'severity', 'src_ip', 'dst_ip',
                       'protocol', 'binary_confidence', 'status', 'detected_at')
    list_filter     = ('attack_type', 'severity', 'status', 'protocol', 'is_attack')
    search_fields   = ('src_ip', 'dst_ip', 'attack_type')
    ordering        = ('-detected_at',)
    readonly_fields = ('detected_at', 'updated_at', 'features')
    fieldsets = (
        ('Détection ML', {
            'fields': ('attack_type', 'severity', 'is_attack',
                       'binary_confidence', 'attack_confidence')
        }),
        ('Réseau', {
            'fields': ('src_ip', 'dst_ip', 'protocol', 'src_bytes', 'dst_bytes', 'duration')
        }),
        ('Features', {
            'fields': ('features',),
            'classes': ('collapse',),
        }),
        ('Statut', {
            'fields': ('status', 'action_taken')
        }),
        ('Timestamps', {
            'fields': ('detected_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )


@admin.register(BlacklistedIP)
class BlacklistedIPAdmin(admin.ModelAdmin):
    list_display  = ('ip_address', 'reason', 'blocked_by', 'alert_count', 'is_active', 'created_at')
    list_filter   = ('blocked_by', 'is_active')
    search_fields = ('ip_address', 'reason')
    ordering      = ('-created_at',)
    actions       = ['debloquer_ips']

    @admin.action(description='Débloquer les IPs sélectionnées')
    def debloquer_ips(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} IP(s) débloquée(s)")


@admin.register(WhitelistedIP)
class WhitelistedIPAdmin(admin.ModelAdmin):
    list_display  = ('ip_address', 'description', 'created_at')
    search_fields = ('ip_address', 'description')
    ordering      = ('-created_at',)


@admin.register(IDSSettings)
class IDSSettingsAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'network_name', 'network_latitude', 'network_longitude', 'updated_at', 'updated_by')
    readonly_fields = ('updated_at', 'updated_by')
    fieldsets = (
        ('Détection', {
            'fields': ('binary_threshold', 'confidence_alert')
        }),
        ('Seuils par classe', {
            'fields': (
                'threshold_dos', 'threshold_ddos', 'threshold_probe',
                'threshold_r2l', 'threshold_u2r', 'threshold_bruteforce',
                'threshold_webattack', 'threshold_botnet', 'threshold_infiltration',
            ),
            'classes': ('collapse',),
        }),
        ('Blocage automatique', {
            'fields': ('auto_block_enabled', 'auto_block_threshold', 'auto_block_duration')
        }),
        ('Apprentissage en ligne (River)', {
            'fields': ('river_enabled', 'river_learn_threshold')
        }),
        ('Notifications', {
            'fields': (
                'notif_enabled', 'notif_telegram_token', 'notif_telegram_chat',
                'notif_email', 'notif_webhook_url', 'notif_min_severity',
            ),
            'classes': ('collapse',),
        }),
        ('Localisation du réseau surveillé', {
            'fields': ('network_name', 'network_latitude', 'network_longitude'),
            'description': 'Coordonnées affichées sur la Threat Map. Trouvez vos coordonnées sur latlong.net',
        }),
        ('Meta', {
            'fields': ('updated_at', 'updated_by'),
            'classes': ('collapse',),
        }),
    )

    def has_add_permission(self, request):
        # Singleton — empêcher la création d'une deuxième instance
        return not IDSSettings.objects.exists()

    def has_delete_permission(self, request, obj=None):
        # Singleton — empêcher la suppression
        return False