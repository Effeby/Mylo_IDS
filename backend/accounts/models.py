from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    ROLES = [
        ('admin',    'Administrateur'),
        ('analyst',  'Analyste SOC'),
        ('viewer',   'Observateur'),
    ]
    role       = models.CharField(max_length=20, choices=ROLES, default='analyst')
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username} ({self.role})"