from django.urls import path
from . import views
from .views import (
    AlertListView, AlertDetailView, AlertStatsView,
    AnalyzeView, BlacklistView, SettingsView, TimelineView,
    AssetListView, AssetDetailView, AssetDiscoverView,
    IPBaselineListView, IPBaselineDetailView, BehavioralStatsView,
    CorrelationListView, CorrelationDetailView, CorrelationStatsView, CopilotAgentView,
)

urlpatterns = [
    path('',           AlertListView.as_view(),      name='alert-list'),
    path('<int:pk>/',  AlertDetailView.as_view(),     name='alert-detail'),
    path('stats/',     AlertStatsView.as_view(),      name='alert-stats'),
    path('analyze/',   AnalyzeView.as_view(),         name='analyze'),
    path('blacklist/', BlacklistView.as_view(),       name='blacklist'),
    path('settings/',      SettingsView.as_view(),        name='ids-settings'),
    path('wazuh-status/',  views.WazuhStatusView.as_view(), name='wazuh-status'),
    path('assets/',        AssetListView.as_view(),       name='asset-list'),
    path('assets/discover/', AssetDiscoverView.as_view(), name='asset-discover'),
    path('assets/<int:pk>/', AssetDetailView.as_view(), name='asset-detail'),
    path('timeline/',  TimelineView.as_view(),        name='timeline'),

    # Analyse comportementale
    path('baselines/',          IPBaselineListView.as_view(),   name='baseline-list'),
    path('baselines/stats/',    BehavioralStatsView.as_view(),  name='baseline-stats'),
    path('baselines/<str:ip>/', IPBaselineDetailView.as_view(), name='baseline-detail'),

    # Corrélation d'alertes
    path('correlations/',            CorrelationListView.as_view(),   name='correlation-list'),
    path('correlations/stats/',      CorrelationStatsView.as_view(),  name='correlation-stats'),
    path('correlations/<int:pk>/',   CorrelationDetailView.as_view(), name='correlation-detail'),

    path("mobile/dashboard/", views.mobile_dashboard, name="mobile-dashboard"),
    
    path('baseline/phase/', views.baseline_phase, name='baseline-phase'),

    path('api/copilot/agent/', CopilotAgentView.as_view()),
]