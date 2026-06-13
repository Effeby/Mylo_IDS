"""
Permissions RBAC pour Mylo IPS.
Utilisation dans les vues :
    permission_classes = [IsAuthenticated, CanBlockIP]
"""
from rest_framework.permissions import BasePermission


class IsSuperAdmin(BasePermission):
    """Réservé à l'équipe Mylo (niveau 5)."""
    message = "Accès réservé aux Super Administrateurs Mylo."
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_super_admin


class IsOrgAdmin(BasePermission):
    """Admin d'organisation ou super admin (niveau 4+)."""
    message = "Accès réservé aux Administrateurs d'organisation."
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.can_manage_users


class IsSOCManager(BasePermission):
    """Manager SOC ou supérieur (niveau 3+)."""
    message = "Accès réservé aux Managers SOC."
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.can_configure_ids


class CanBlockIP(BasePermission):
    """Analyste SOC ou supérieur (niveau 2+)."""
    message = "Vous n'avez pas l'autorisation de bloquer des IPs."
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.can_block_ip


class CanFeedbackRiver(BasePermission):
    """Analyste SOC ou supérieur (niveau 2+)."""
    message = "Vous n'avez pas l'autorisation de donner du feedback au modèle."
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.can_feedback_river


class CanGenerateReports(BasePermission):
    """Tous les utilisateurs authentifiés."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.can_generate_reports


class SameOrganisation(BasePermission):
    """Vérifie que l'objet appartient à la même organisation."""
    message = "Vous n'avez pas accès aux données de cette organisation."
    def has_object_permission(self, request, view, obj):
        if request.user.is_super_admin:
            return True
        org = getattr(obj, 'organisation', None)
        return org == request.user.organisation