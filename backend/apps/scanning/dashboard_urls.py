from django.urls import path
from . import views

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('trends/', views.DashboardTrendsView.as_view(), name='dashboard-trends'),
]
