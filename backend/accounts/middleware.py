"""
Middleware de tenant — injecte l'organisation dans chaque requête.
Ajouter dans settings.py MIDDLEWARE :
    'accounts.middleware.TenantMiddleware',
"""


class TenantMiddleware:
    """
    Injecte request.organisation depuis le user authentifié.
    Permet aux vues d'accéder facilement au tenant courant.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Injecter l'organisation si l'utilisateur est authentifié
        if hasattr(request, 'user') and request.user.is_authenticated:
            request.organisation = getattr(request.user, 'organisation', None)
        else:
            request.organisation = None

        response = self.get_response(request)
        return response


class AuditMiddleware:
    """
    Middleware d'audit automatique — logue les requêtes importantes.
    """
    AUDITED_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
    EXCLUDED_PATHS  = {
        '/api/auth/refresh/',
        '/api/alerts/analyze/',  # trop fréquent
        '/api/actions/river/learn/',
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Logger seulement les mutations importantes
        if (request.method in self.AUDITED_METHODS
                and request.path not in self.EXCLUDED_PATHS
                and hasattr(request, 'user')
                and request.user.is_authenticated):
            try:
                self._log(request, response)
            except Exception:
                pass  # Ne jamais bloquer une requête à cause de l'audit

        return response

    def _log(self, request, response):
        from accounts.models import AuditLog

        # Déterminer l'action depuis le path et la méthode
        action = self._detect_action(request)
        if not action:
            return

        ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
        if not ip:
            ip = request.META.get('REMOTE_ADDR')

        AuditLog.log(
            action      = action,
            user        = request.user,
            ip_address  = ip or None,
            user_agent  = request.META.get('HTTP_USER_AGENT', ''),
            method      = request.method,
            endpoint    = request.path,
            status_code = response.status_code,
            success     = response.status_code < 400,
        )

    def _detect_action(self, request):
        path   = request.path
        method = request.method

        if '/api/auth/login/'   in path: return 'login'
        if '/api/auth/logout/'  in path: return 'logout'
        if '/api/alerts/blacklist/' in path:
            return 'ip_block' if method == 'POST' else 'ip_unblock'
        if '/api/alerts/settings/' in path and method in ('PUT', 'PATCH'):
            return 'settings_update'
        if '/api/reports/'      in path: return 'report_generate'
        if '/api/alerts/' in path and method == 'PATCH':
            return 'alert_status_update'
        return None