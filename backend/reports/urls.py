from django.urls import path
from .views import ExportCSVView, ExportJSONView, GenerateReportView, GeneratePDFView
from . import views

urlpatterns = [
    path('export/csv/',  ExportCSVView.as_view(),   name='export-csv'),
    path('export/json/', ExportJSONView.as_view(),  name='export-json'),
    path('generate/',    GenerateReportView.as_view(), name='generate-report'),
    path('pdf/',         GeneratePDFView.as_view(),    name='generate-pdf'),
    path("config/",   views.report_config,     name="report-config"),
    path("trigger/",  views.trigger_report_now, name="report-trigger"),
    path("preview/",  views.preview_report,     name="report-preview"),
]
