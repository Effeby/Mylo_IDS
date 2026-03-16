from django.db import models

# Create your models here.
from django.db import models

class RiverMetrics(models.Model):
    """Historique des métriques River après chaque apprentissage."""
    accuracy      = models.FloatField(default=0)
    total_learned = models.IntegerField(default=0)
    dos_learned   = models.IntegerField(default=0)
    ddos_learned  = models.IntegerField(default=0)
    probe_learned = models.IntegerField(default=0)
    r2l_learned   = models.IntegerField(default=0)
    u2r_learned   = models.IntegerField(default=0)
    brute_learned = models.IntegerField(default=0)
    web_learned   = models.IntegerField(default=0)
    bot_learned   = models.IntegerField(default=0)
    infil_learned = models.IntegerField(default=0)
    recorded_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-recorded_at']

    def __str__(self):
        return f"River @ {self.recorded_at} — acc: {self.accuracy:.2%}"