from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.core.mail import send_mail
from django.utils.text import slugify
from .models import AuditLog, Organisation
from rest_framework.decorators import api_view, permission_classes
from .totp import generate_totp_secret, get_totp_uri, verify_totp_code, generate_qr_base64

User = get_user_model()


def get_client_ip(request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
    return ip or request.META.get('REMOTE_ADDR')


def serialize_user(user):
    return {
        'id':                 user.id,
        'username':           user.username,
        'email':              user.email,
        'role':               user.role,
        'role_display':       user.get_role_display(),
        'habilitation_level': user.habilitation_level,
        'fullname':           user.get_full_name() or user.username,
        'poste':              user.poste,
        'phone':              user.phone,
        'totp_enabled':       user.totp_enabled,
        'password_must_change': user.password_must_change,
        'organisation': {
            'id':            user.organisation.id,
            'name':          user.organisation.name,
            'slug':          user.organisation.slug,
            'email':         user.organisation.email,
            'plan':          user.organisation.plan,
            'sector':        user.organisation.sector,
            'is_setup_done': user.organisation.is_setup_done,
            'network_name':  user.organisation.network_name,
        } if user.organisation else None,
        'is_locked':  user.is_locked,
        'is_active':  user.is_active,
        'permissions': {
            'can_block_ip':             user.can_block_ip,
            'can_feedback_river':       user.can_feedback_river,
            'can_configure_ids':        user.can_configure_ids,
            'can_manage_users':         user.can_manage_users,
            'can_manage_organisations': user.can_manage_organisations,
            'can_generate_reports':     user.can_generate_reports,
        }
    }


# ─── INSCRIPTION (publique) ───────────────────────────────────────────────────
class RegisterView(APIView):
    """
    Crée le premier compte admin + l'organisation.
    Accessible sans authentification.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        d = request.data

        # Validation
        required = ['username', 'password', 'email', 'org_name']
        for field in required:
            if not d.get(field, '').strip():
                return Response({'error': f'Le champ {field} est requis'}, status=400)

        if User.objects.filter(username=d['username']).exists():
            return Response({'error': 'Ce nom d\'utilisateur existe déjà'}, status=400)

        if User.objects.filter(email=d['email']).exists():
            return Response({'error': 'Cet email est déjà utilisé'}, status=400)

        # Créer l'organisation
        slug = slugify(d['org_name'])
        # S'assurer que le slug est unique
        base_slug = slug
        counter   = 1
        while Organisation.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1

        org_email = (d.get('org_email') or d.get('email', '')).strip()
        if not org_email:
            org_email = d.get('email', '').strip()

        org = Organisation.objects.create(
            name          = d['org_name'],
            slug          = slug,
            email         = org_email,
            sector        = d.get('sector', 'other'),
            plan          = 'free',
            is_setup_done = False,  # Wizard pas encore fait
        )

        # Créer le premier utilisateur (org_admin)
        user = User.objects.create_user(
            username           = d['username'],
            email              = d['email'],
            password           = d['password'],
            first_name         = d.get('first_name', ''),
            last_name          = d.get('last_name', ''),
            role               = 'org_admin',
            habilitation_level = 4,
            organisation       = org,
        )

        # Créer les settings IDS pour cette org
        try:
            from alerts.models import IDSSettings
            IDSSettings.objects.get_or_create(organisation=org)
        except Exception:
            pass

        # Log
        AuditLog.log(
            action='user_create', user=user, organisation=org,
            description=f'Inscription — création organisation {org.name}',
            ip_address=get_client_ip(request),
        )

        # Générer les tokens JWT
        refresh = RefreshToken.for_user(user)
        return Response({
            'access':  str(refresh.access_token),
            'refresh': str(refresh),
            'user':    serialize_user(user),
        }, status=201)


# ─── LOGIN ────────────────────────────────────────────────────────────────────
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        ip       = get_client_ip(request)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            AuditLog.log(
                action='login_failed',
                description=f'Tentative avec username: {username}',
                ip_address=ip, success=False,
            )
            return Response({'error': 'Identifiants incorrects'}, status=401)

        if not user.check_password(password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.is_locked = True
            user.save(update_fields=['failed_login_attempts', 'is_locked'])
            AuditLog.log(
                action='login_failed', user=user,
                description=f'Mot de passe incorrect (tentative {user.failed_login_attempts})',
                ip_address=ip, success=False,
            )
            return Response({'error': 'Identifiants incorrects'}, status=401)

        if not user.is_active:
            return Response({'error': 'Compte désactivé'}, status=403)

        if user.is_locked:
            return Response({'error': 'Compte verrouillé — contactez votre administrateur'}, status=403)

        user.failed_login_attempts = 0
        user.last_login_ip = ip
        user.save(update_fields=['failed_login_attempts', 'last_login_ip'])

        # Sauvegarder les credentials dans .env.capture pour capture.py
        # Seulement pour les rôles qui peuvent configurer l'IDS (niveau 3+)
        if user.habilitation_level >= 3:
            try:
                from pathlib import Path
                from datetime import datetime
                base_dir = Path(__file__).resolve().parent.parent.parent
                env_file = base_dir / '.env.capture'

                # Supprimer l'ancien fichier s'il existe
                if env_file.exists():
                    env_file.unlink()

                # Recréer avec les nouvelles infos
                env_file.write_text(
                    f"# Généré automatiquement par Mylo IPS au login\n"
                    f"# Ne pas partager ce fichier\n"
                    f"CAPTURE_USERNAME={user.username}\n"
                    f"CAPTURE_PASSWORD={request.data.get('password', '')}\n"
                    f"CAPTURE_ORG={user.organisation.slug if user.organisation else 'default'}\n"
                    f"CAPTURE_LOGIN_AT={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"CAPTURE_LOGIN_IP={ip}\n"
                    f"CAPTURE_DEVICE={request.META.get('HTTP_USER_AGENT', 'unknown')[:80]}\n",
                    encoding='utf-8'
                )
            except Exception as e:
                print(f"  ⚠ .env.capture non sauvegardé: {e}")

        AuditLog.log(
            action='login', user=user,
            description=f'Connexion depuis {ip}',
            ip_address=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        refresh = RefreshToken.for_user(user)
        response_data = {
            'user': serialize_user(user),
        }

        if user.password_must_change:
            response_data.update({
                'requires_password_change': True,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            })
            return Response(response_data)

        if user.totp_enabled:
            # Envoi un jeton temporaire pour la vérification TOTP uniquement
            response_data.update({
                'requires_totp': True,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            })
        else:
            response_data.update({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            })

        return Response(response_data)


# ─── LOGOUT ───────────────────────────────────────────────────────────────────
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        AuditLog.log(action='logout', user=request.user, ip_address=get_client_ip(request))
        try:
            token = RefreshToken(request.data.get('refresh'))
            token.blacklist()
        except Exception:
            pass
        return Response({'message': 'Déconnexion réussie'})


# ─── ME ───────────────────────────────────────────────────────────────────────
class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(serialize_user(request.user))

    def patch(self, request):
        user    = request.user
        allowed = ['first_name', 'last_name', 'email', 'poste', 'phone']
        for field in allowed:
            if field in request.data:
                setattr(user, field, request.data[field])

        password = request.data.get('password')
        current_password = request.data.get('current_password')
        if password:
            if user.password_must_change or user.check_password(current_password or ''):
                user.set_password(password)
                user.password_must_change = False
            else:
                return Response({'error': 'Ancien mot de passe incorrect.'}, status=400)

        user.save()
        AuditLog.log(
            action='user_update', user=user,
            description='Mise à jour profil personnel',
            ip_address=get_client_ip(request),
        )
        return Response(serialize_user(user))


# ─── USERS ────────────────────────────────────────────────────────────────────
class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.can_manage_users:
            return Response({'error': 'Permission insuffisante'}, status=403)
        if request.user.is_super_admin:
            users = User.objects.all().select_related('organisation')
        else:
            users = User.objects.filter(
                organisation=request.user.organisation
            ).select_related('organisation')
        return Response([serialize_user(u) for u in users])

    def post(self, request):
        if not request.user.can_manage_users:
            return Response({'error': 'Permission insuffisante'}, status=403)
        d = request.data
        if User.objects.filter(username=d.get('username')).exists():
            return Response({'error': 'Ce nom d\'utilisateur existe déjà'}, status=400)

        role  = d.get('role', 'soc_analyst')
        level = d.get('habilitation_level', 2)

        user = User.objects.create_user(
            username           = d.get('username'),
            email              = d.get('email', ''),
            password           = d.get('password'),
            first_name         = d.get('first_name', ''),
            last_name          = d.get('last_name', ''),
            role               = role,
            habilitation_level = level,
            poste              = d.get('poste', ''),
            phone              = d.get('phone', ''),
            organisation       = request.user.organisation,
            password_must_change = True,
        )
        AuditLog.log(
            action='user_create', user=request.user,
            description=f'Création utilisateur {user.username} ({user.get_role_display()})',
            object_type='User', object_id=user.id, object_repr=str(user),
            ip_address=get_client_ip(request),
        )
        return Response(serialize_user(user), status=201)


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_user(self, pk, request):
        try:
            user = User.objects.get(pk=pk)
            if not request.user.is_super_admin:
                if user.organisation != request.user.organisation:
                    return None
            return user
        except User.DoesNotExist:
            return None

    def patch(self, request, pk):
        if not request.user.can_manage_users:
            return Response({'error': 'Permission insuffisante'}, status=403)
        user = self._get_user(pk, request)
        if not user:
            return Response({'error': 'Utilisateur introuvable'}, status=404)
        allowed = ['first_name', 'last_name', 'email', 'role',
                   'habilitation_level', 'poste', 'phone', 'is_active', 'is_locked']
        for field in allowed:
            if field in request.data:
                setattr(user, field, request.data[field])
        user.save()
        AuditLog.log(
            action='user_update', user=request.user,
            description=f'Modification utilisateur {user.username}',
            object_type='User', object_id=user.id,
            ip_address=get_client_ip(request),
        )
        return Response(serialize_user(user))

    def delete(self, request, pk):
        if not request.user.can_manage_users:
            return Response({'error': 'Permission insuffisante'}, status=403)
        user = self._get_user(pk, request)
        if not user:
            return Response({'error': 'Utilisateur introuvable'}, status=404)
        if user == request.user:
            return Response({'error': 'Vous ne pouvez pas vous supprimer'}, status=400)
        AuditLog.log(
            action='user_delete', user=request.user,
            description=f'Suppression utilisateur {user.username}',
            ip_address=get_client_ip(request),
        )
        user.delete()
        return Response({'message': 'Utilisateur supprimé'})


# ─── ORGANISATION ─────────────────────────────────────────────────────────────
class OrganisationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        org = request.user.organisation
        if not org:
            return Response({'error': 'Aucune organisation'}, status=404)
        return Response({
            'id':                org.id,
            'name':              org.name,
            'slug':              org.slug,
            'email':             org.email,
            'phone':             org.phone,
            'website':           org.website,
            'sector':            org.sector,
            'plan':              org.plan,
            'is_setup_done':     org.is_setup_done,
            'network_name':      org.network_name,
            'network_latitude':  org.network_latitude,
            'network_longitude': org.network_longitude,
            'network_address':   org.network_address,
            'created_at':        org.created_at.isoformat(),
            'members_count':     org.members.count(),
        })

    def put(self, request):
        if not request.user.can_manage_users:
            return Response({'error': 'Permission insuffisante'}, status=403)
        org     = request.user.organisation
        allowed = ['name', 'email', 'phone', 'website', 'sector',
                   'network_name', 'network_latitude', 'network_longitude', 'network_address']
        for field in allowed:
            if field in request.data:
                setattr(org, field, request.data[field])
        org.save()
        AuditLog.log(
            action='org_update', user=request.user,
            description=f'Modification organisation {org.name}',
            ip_address=get_client_ip(request),
        )
        return Response({'status': 'ok'})


# ─── ONBOARDING ───────────────────────────────────────────────────────────────
class OnboardingView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        org  = request.user.organisation
        if not org:
            return Response({'error': 'Aucune organisation associée'}, status=400)

        d = request.data

        # ── Étape 1 — Infos organisation ──────────────────────────
        if 'name'    in d: org.name    = d['name']
        if 'email'   in d: org.email   = d['email']
        if 'sector'  in d: org.sector  = d['sector']
        if 'website' in d: org.website = d['website']
        if 'phone'   in d: org.phone   = d['phone']

        # ── Étape 2 — Localisation réseau ─────────────────────────
        if 'network_name'    in d: org.network_name    = d['network_name']
        if 'network_address' in d: org.network_address = d['network_address']
        if 'network_latitude' in d:
            try: org.network_latitude = float(d['network_latitude'])
            except (ValueError, TypeError): pass
        if 'network_longitude' in d:
            try: org.network_longitude = float(d['network_longitude'])
            except (ValueError, TypeError): pass

        # Marquer l'onboarding comme complété
        org.is_setup_done = True
        org.save()

        # ── Mettre à jour IDSSettings ──────────────────────────────
        try:
            from alerts.models import IDSSettings
            ids, _ = IDSSettings.objects.get_or_create(organisation=org)

            # Mode IDS
            ids_mode = d.get('ids_mode', 'observation')
            ids.auto_block_enabled = (ids_mode == 'active')
            if 'auto_block_threshold' in d:
                try: ids.auto_block_threshold = float(d['auto_block_threshold'])
                except (ValueError, TypeError): pass

            # Notifications
            if 'notif_enabled'        in d: ids.notif_enabled        = bool(d['notif_enabled'])
            if 'notif_telegram_token' in d: ids.notif_telegram_token = d['notif_telegram_token']
            if 'notif_telegram_chat'  in d: ids.notif_telegram_chat  = d['notif_telegram_chat']
            if 'notif_email'          in d: ids.notif_email          = d['notif_email']
            if 'notif_min_severity'   in d: ids.notif_min_severity   = d['notif_min_severity']

            # Localisation
            ids.network_name      = org.network_name
            ids.network_latitude  = org.network_latitude
            ids.network_longitude = org.network_longitude
            ids.updated_by        = request.user.username
            ids.save()
        except Exception as e:
            print(f"  ⚠ IDSSettings erreur: {e}")

        AuditLog.log(
            action='onboarding_complete', user=request.user, organisation=org,
            description=f'Onboarding complété pour {org.name}',
            ip_address=get_client_ip(request),
        )

        return Response({
            'status':   'ok',
            'message':  f'Bienvenue sur Mylo IPS, {org.name} !',
            'redirect': '/dashboard',
        })


# ─── AUDIT LOG ────────────────────────────────────────────────────────────────
class AuditLogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.can_manage_users:
            return Response({'error': 'Permission insuffisante'}, status=403)
        limit   = int(request.query_params.get('limit', 100))
        action  = request.query_params.get('action')
        user_id = request.query_params.get('user_id')

        if request.user.is_super_admin:
            qs = AuditLog.objects.all()
        else:
            qs = AuditLog.objects.filter(organisation=request.user.organisation)

        if action:   qs = qs.filter(action=action)
        if user_id:  qs = qs.filter(user_id=user_id)

        logs = qs.select_related('user', 'organisation')[:limit]
        return Response([{
            'id':             log.id,
            'timestamp':      log.timestamp.isoformat(),
            'user':           log.username,
            'action':         log.action,
            'action_display': log.get_action_display(),
            'description':    log.description,
            'object_type':    log.object_type,
            'object_repr':    log.object_repr,
            'ip_address':     str(log.ip_address) if log.ip_address else None,
            'endpoint':       log.endpoint,
            'method':         log.method,
            'status_code':    log.status_code,
            'success':        log.success,
            'organisation':   log.organisation.name if log.organisation else None,
        } for log in logs])


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def totp_setup(request):
    """
    Génère un secret TOTP + QR code pour l'utilisateur.
    L'utilisateur scanne le QR dans Google Authenticator.
    """
    user = request.user
    if not user.totp_secret:
        user.totp_secret = generate_totp_secret()
        user.save(update_fields=["totp_secret"])

    uri = get_totp_uri(user.totp_secret, user.username)
    qr_base64 = generate_qr_base64(uri)

    return Response({
        "secret": user.totp_secret,
        "qr_code": f"data:image/png;base64,{qr_base64}",
        "totp_enabled": user.totp_enabled,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_activate(request):
    """
    Vérifie le premier code TOTP et active la double auth.
    Body: { "code": "123456" }
    """
    user = request.user
    code = request.data.get("code", "")

    if not user.totp_secret:
        return Response(
            {"error": "TOTP non initialisé. Appelez /totp/setup/ d'abord."},
            status=status.HTTP_400_BAD_REQUEST
        )

    if verify_totp_code(user.totp_secret, code):
        user.totp_enabled = True
        user.save(update_fields=["totp_enabled"])
        return Response({"message": "Double authentification activée avec succès."})

    return Response(
        {"error": "Code invalide. Vérifiez l'heure de votre appareil."},
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_verify(request):
    """
    Vérifie le code TOTP lors de la connexion (2ème étape).
    Body: { "code": "123456" }
    Retourne un token JWT complet si le code est valide.
    """
    user = request.user
    code = request.data.get("code", "")

    if not user.totp_enabled:
        return Response({"error": "2FA non activée."}, status=status.HTTP_400_BAD_REQUEST)

    if verify_totp_code(user.totp_secret, code):
        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Authentification réussie.",
            "totp_verified": True,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": serialize_user(user),
        })

    return Response(
        {"error": "Code incorrect ou expiré."},
        status=status.HTTP_401_UNAUTHORIZED
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_disable(request):
    """
    Désactive la double auth.
    Body: { "code": "123456" }
    """
    user = request.user
    code = request.data.get("code", "")

    if not verify_totp_code(user.totp_secret, code):
        return Response(
            {"error": "Code invalide."},
            status=status.HTTP_400_BAD_REQUEST
        )

    user.totp_enabled = False
    user.totp_secret = None
    user.save(update_fields=["totp_enabled", "totp_secret"])
    return Response({"message": "Double authentification désactivée."})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_reset(request, user_id):
    """
    Réinitialise le secret TOTP d'un utilisateur par un administrateur
    et notifie l'utilisateur par email.
    """
    if not request.user.can_configure_ids:
        return Response({'error': 'Permission insuffisante'}, status=403)

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response({'error': 'Utilisateur introuvable'}, status=404)

    if not request.user.is_super_admin and user.organisation != request.user.organisation:
        return Response({'error': 'Utilisateur introuvable'}, status=404)

    user.totp_secret = generate_totp_secret()
    user.totp_enabled = False
    user.save(update_fields=["totp_enabled", "totp_secret"])

    if not user.email:
        return Response({'error': 'Cet utilisateur n\'a pas d\'email renseigné.'}, status=400)

    subject = 'Réinitialisation de votre authentification TOTP Mylo IPS'
    message = (
        f'Bonjour {user.get_full_name() or user.username},\n\n'
        'Votre authentification TOTP a été réinitialisée par un administrateur. '
        'À votre prochaine connexion, vous devrez reconfigurer votre application d\'authentification TOTP.\n\n'
        'Si vous n\'avez pas demandé cette réinitialisation, contactez votre administrateur.'
    )

    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
    except Exception as exc:
        AuditLog.log(
            action='user_update', user=request.user,
            description=f'Échec envoi email reset TOTP pour {user.username}: {exc}',
            object_type='User', object_id=user.id, object_repr=str(user),
            ip_address=get_client_ip(request), success=False,
        )
        return Response({'error': 'Impossible d\'envoyer l\'email de notification.'}, status=500)

    AuditLog.log(
        action='user_update', user=request.user,
        description=f'Réinitialisation TOTP pour {user.username}',
        object_type='User', object_id=user.id, object_repr=str(user),
        ip_address=get_client_ip(request),
    )
    return Response({'message': 'TOTP réinitialisé et notification envoyée.'})