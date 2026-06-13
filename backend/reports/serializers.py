from rest_framework import serializers
from .models import ReportConfig


class ReportConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportConfig
        fields = ["report_email", "send_hour", "send_minute", "is_active", "updated_at"]
        read_only_fields = ["updated_at"]

    def validate_send_hour(self, value):
        if not 0 <= value <= 23:
            raise serializers.ValidationError("L'heure doit être entre 0 et 23.")
        return value

    def validate_send_minute(self, value):
        if not 0 <= value <= 59:
            raise serializers.ValidationError("Les minutes doivent être entre 0 et 59.")
        return value