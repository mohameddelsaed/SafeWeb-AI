from django.urls import path
from . import views

urlpatterns = [
    path('', views.ScanListView.as_view(), name='scan-list'),
]
