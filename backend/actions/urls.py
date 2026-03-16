from django.urls import path
from .views import RiverLearnView, RiverPredictView, RiverStatusView

urlpatterns = [
    path('river/learn/',   RiverLearnView.as_view(),   name='river-learn'),
    path('river/predict/', RiverPredictView.as_view(), name='river-predict'),
    path('river/status/',  RiverStatusView.as_view(),  name='river-status'),
]