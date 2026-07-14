from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.AdminDashboardView.as_view(), name='admin-dashboard'),
    path('users/', views.AdminUsersView.as_view(), name='admin-users'),
    path('users/<uuid:user_id>/', views.AdminUserDetailView.as_view(), name='admin-user-detail'),
    path('scans/', views.AdminScansView.as_view(), name='admin-scans'),
    path('scans/<uuid:scan_id>/', views.AdminScanDetailView.as_view(), name='admin-scan-detail'),
    path('ml/', views.AdminMLView.as_view(), name='admin-ml'),
    path('settings/', views.AdminSettingsView.as_view(), name='admin-settings'),
    path('contacts/', views.AdminContactsView.as_view(), name='admin-contacts'),
    path('contacts/<uuid:message_id>/', views.AdminContactDetailView.as_view(), name='admin-contact-detail'),
    path('applications/', views.AdminJobApplicationsView.as_view(), name='admin-applications'),
    path('applications/<uuid:application_id>/', views.AdminJobApplicationDetailView.as_view(), name='admin-application-detail'),
]
