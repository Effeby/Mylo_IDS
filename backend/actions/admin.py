from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import RiverMetrics

@admin.register(RiverMetrics)
class RiverMetricsAdmin(admin.ModelAdmin):
    list_display  = ('recorded_at', 'accuracy_pct', 'total_learned',
                     'dos_learned', 'ddos_learned', 'probe_learned',
                     'r2l_learned', 'u2r_learned', 'brute_learned',
                     'web_learned', 'bot_learned', 'infil_learned')
    ordering      = ('-recorded_at',)
    readonly_fields = ('recorded_at',)

    def accuracy_pct(self, obj):
        return f"{obj.accuracy:.2%}"
    accuracy_pct.short_description = 'Accuracy'