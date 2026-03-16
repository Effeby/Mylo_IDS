#!/usr/bin/env python
"""Setup initial — crée les utilisateurs Mylo."""
import os, sys, django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

print("=" * 45)
print("  MYLO Backend — Setup initial")
print("=" * 45)

users = [
    dict(username='admin',   password='mylo2025',    email='admin@securebank.ci',
         role='admin',   first_name='Admin',    last_name='SecureBank', is_superuser=True, is_staff=True),
    dict(username='analyst', password='analyst2025', email='analyst@securebank.ci',
         role='analyst', first_name='Analyste', last_name='SOC',        is_superuser=False, is_staff=False),
]

for u in users:
    is_super = u.pop('is_superuser')
    is_staff = u.pop('is_staff')
    pwd      = u.pop('password')
    if not User.objects.filter(username=u['username']).exists():
        if is_super:
            user = User.objects.create_superuser(password=pwd, **u)
        else:
            user = User.objects.create_user(password=pwd, **u)
        print(f"  ✓ {u['username']} créé ({u['username']} / {pwd})")
    else:
        print(f"  ✓ {u['username']} existe déjà")

print("\n  Lancement :")
print("  python manage.py runserver 8001")
print("=" * 45)