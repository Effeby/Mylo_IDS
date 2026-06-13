from django.contrib import admin
from .models import ReportConfig

# Register your models here.@admin.register(ReportConfig)
class ReportConfigAdmin(admin.ModelAdmin):
    list_display = [
        "organisation",
        "report_email",
        "send_hour",
        "send_minute",
        "is_active",
        "updated_at",
    ]
    list_filter = ["is_active", "send_hour"]
    search_fields = ["organisation__name", "report_email"]
    readonly_fields = ["created_at", "updated_at"]
    ordering = ["organisation__name"]

    fieldsets = (
        ("Organisation", {
            "fields": ("organisation",)
        }),
        ("Destinataire", {
            "fields": ("report_email",)
        }),
        ("Planification", {
            "fields": ("send_hour", "send_minute", "is_active"),
            "description": "Heure d'envoi quotidien (timezone Africa/Abidjan)."
        }),
        ("Métadonnées", {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",)
        }),
    )

    actions = ["activer_rapports", "desactiver_rapports", "envoyer_maintenant"]

    @admin.action(description="✅ Activer les rapports sélectionnés")
    def activer_rapports(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} rapport(s) activé(s).")

    @admin.action(description="⛔ Désactiver les rapports sélectionnés")
    def desactiver_rapports(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} rapport(s) désactivé(s).")

    @admin.action(description="📤 Envoyer le rapport maintenant")
    def envoyer_maintenant(self, request, queryset):
        from reports.tasks import send_daily_reports
        send_daily_reports.delay()
        self.message_user(
            request,
            f"Génération lancée pour {queryset.count()} organisation(s)."
        )