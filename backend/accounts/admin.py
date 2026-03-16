from django.contrib import admin

# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

@admin.register(User)
class MyloUserAdmin(UserAdmin):
    list_display  = ('username', 'email', 'role', 'is_active', 'last_login_ip', 'created_at')
    list_filter   = ('role', 'is_active', 'is_staff')
    search_fields = ('username', 'email')
    ordering      = ('-created_at',)

    fieldsets = UserAdmin.fieldsets + (
        ('Mylo', {'fields': ('role', 'last_login_ip')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Mylo', {'fields': ('role',)}),
    )