from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Organisation, AuditLog


@admin.register(Organisation)
class OrganisationAdmin(admin.ModelAdmin):
    list_display  = ('name', 'slug', 'email', 'sector', 'plan', 'is_active', 'is_setup_done', 'created_at')
    list_filter   = ('plan', 'sector', 'is_active', 'is_setup_done')
    search_fields = ('name', 'slug', 'email')
    prepopulated_fields = {'slug': ('name',)}
    fieldsets = (
        ('Identité', {
            'fields': ('name', 'slug', 'email', 'phone', 'website', 'logo_url')
        }),
        ('Classification', {
            'fields': ('sector', 'plan', 'is_active', 'is_setup_done')
        }),
        ('Localisation réseau', {
            'fields': ('network_name', 'network_latitude', 'network_longitude', 'network_address')
        }),
    )


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display  = ('username', 'email', 'organisation', 'role',
                     'habilitation_level', 'poste', 'is_active', 'is_locked')
    list_filter   = ('role', 'habilitation_level', 'is_active', 'is_locked', 'organisation')
    search_fields = ('username', 'email', 'poste', 'organisation__name')
    ordering      = ('organisation', 'role', 'username')

    fieldsets = BaseUserAdmin.fieldsets + (
        ('Mylo IPS', {
            'fields': ('organisation', 'role', 'habilitation_level', 'poste', 'phone')
        }),
        ('Sécurité', {
            'fields': ('last_login_ip', 'failed_login_attempts', 'is_locked')
        }),
    )

    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Mylo IPS', {
            'fields': ('organisation', 'role', 'habilitation_level', 'poste')
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display  = ('timestamp', 'username', 'organisation', 'action',
                     'ip_address', 'success', 'status_code')
    list_filter   = ('action', 'success', 'organisation')
    search_fields = ('username', 'ip_address', 'description')
    ordering      = ('-timestamp',)
    readonly_fields = ('timestamp', 'user', 'organisation', 'username', 'action',
                       'description', 'ip_address', 'user_agent', 'method',
                       'endpoint', 'status_code', 'success', 'extra_data')

    def has_add_permission(self, request):
        return False  # Les logs ne se créent pas manuellement

    def has_change_permission(self, request, obj=None):
        return False  # Les logs ne se modifient pas

    def has_delete_permission(self, request, obj=None):
        return request.user.is_super_admin if hasattr(request.user, 'is_super_admin') else False