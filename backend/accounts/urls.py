from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from .views import (
    RegisterView, LoginView, LogoutView, MeView,
    UserListView, UserDetailView,
    AuditLogView, OrganisationView, OnboardingView,
)

urlpatterns = [
    # Auth publique
    path('register/',  RegisterView.as_view(),  name='register'),
    path('login/',     LoginView.as_view(),      name='login'),
    path('logout/',    LogoutView.as_view(),     name='logout'),
    path('refresh/',   TokenRefreshView.as_view(), name='token_refresh'),
    path('me/',        MeView.as_view(),         name='me'),

    # Utilisateurs
    path('users/',          UserListView.as_view(),   name='user-list'),
    path('users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),

    # Organisation
    path('organisation/', OrganisationView.as_view(), name='organisation'),

    # Onboarding wizard
    path('onboarding/',   OnboardingView.as_view(),   name='onboarding'),

    # Audit
    path('audit/',        AuditLogView.as_view(),     name='audit-log'),

    path("totp/setup/",    views.totp_setup,    name="totp-setup"),
    path("totp/activate/", views.totp_activate, name="totp-activate"),
    path("totp/verify/",   views.totp_verify,   name="totp-verify"),
    path("totp/disable/",  views.totp_disable,  name="totp-disable"),
    path("totp/reset/<int:user_id>/", views.totp_reset, name="totp-reset"),
]