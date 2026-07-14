from django.urls import path
from . import views

urlpatterns = [
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('profile/api-keys/', views.APIKeyListCreateView.as_view(), name='api-keys'),
    path('profile/api-keys/<str:key_id>/', views.APIKeyDeleteView.as_view(), name='api-key-delete'),
    path('profile/sessions/', views.SessionListView.as_view(), name='sessions'),
    path('profile/2fa/enable/', views.TwoFactorEnableView.as_view(), name='2fa-enable'),
    path('profile/2fa/verify/', views.TwoFactorVerifyView.as_view(), name='2fa-verify'),
    path('settings/', views.UserSettingsView.as_view(), name='settings'),
]
