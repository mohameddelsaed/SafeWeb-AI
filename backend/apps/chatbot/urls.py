from django.urls import path
from . import views

urlpatterns = [
    path('', views.ChatView.as_view(), name='chat'),
    path('sessions/', views.ChatSessionListView.as_view(), name='chat-sessions'),
    path('sessions/<uuid:session_id>/', views.ChatSessionDetailView.as_view(), name='chat-session-detail'),
    path('messages/<uuid:message_id>/feedback/', views.MessageFeedbackView.as_view(), name='chat-message-feedback'),
    path('suggestions/', views.SuggestionsView.as_view(), name='chat-suggestions'),
    path('analytics/', views.ChatAnalyticsView.as_view(), name='chat-analytics'),
]
