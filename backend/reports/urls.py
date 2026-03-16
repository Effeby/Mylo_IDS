from django.urls import path
from .views import ExportCSVView, ExportJSONView, GenerateReportView, GeneratePDFView

urlpatterns = [
    path('export/csv/',  ExportCSVView.as_view(),   name='export-csv'),
    path('export/json/', ExportJSONView.as_view(),  name='export-json'),
    path('generate/',    GenerateReportView.as_view(), name='generate-report'),
    path('pdf/',         GeneratePDFView.as_view(),    name='generate-pdf'),
]