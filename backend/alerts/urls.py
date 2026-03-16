from django.urls import path
from .views import (
    AlertListView, AlertDetailView, AlertStatsView,
    AnalyzeView, BlacklistView, SettingsView, TimelineView,
)
urlpatterns = [
    path('',            AlertListView.as_view(),   name='alert-list'),
    path('<int:pk>/',   AlertDetailView.as_view(), name='alert-detail'),
    path('stats/',      AlertStatsView.as_view(),  name='alert-stats'),
    path('analyze/',    AnalyzeView.as_view(),     name='analyze'),
    path('blacklist/',  BlacklistView.as_view(),   name='blacklist'),
    path('settings/',   SettingsView.as_view(),    name='ids-settings'),
    path('timeline/',   TimelineView.as_view(),    name='timeline'),
]