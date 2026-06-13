from django.db import models
from accounts.models import Organisation

# Create your models here.

class ReportConfig(models.Model):
    """Configuration du rapport automatique par organisation."""
    organisation = models.OneToOneField(
        Organisation,
        on_delete=models.CASCADE,
        related_name="report_config"
    )
    report_email = models.EmailField(
        help_text="Email destinataire du rapport quotidien"
    )
    send_hour = models.PositiveSmallIntegerField(
        default=7,
        help_text="Heure d'envoi (0-23, UTC)"
    )
    send_minute = models.PositiveSmallIntegerField(
        default=0,
        help_text="Minute d'envoi (0-59)"
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuration rapport"
        verbose_name_plural = "Configurations rapports"

    def __str__(self):
        return f"Rapport {self.organisation.name} → {self.report_email} à {self.send_hour:02d}h{self.send_minute:02d}"