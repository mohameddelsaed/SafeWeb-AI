import uuid
from django.db import models
from django.conf import settings


class ChatSession(models.Model):
    """A conversation session between a user and the AI."""
    CONTEXT_CHOICES = [
        ('general', 'General'),
        ('scan', 'Scan'),
        ('vulnerability', 'Vulnerability'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='chat_sessions',
        null=True,
        blank=True,
    )
    scan = models.ForeignKey(
        'scanning.Scan',
        on_delete=models.SET_NULL,
        related_name='chat_sessions',
        null=True,
        blank=True,
    )
    context_type = models.CharField(max_length=20, choices=CONTEXT_CHOICES, default='general')
    session_key = models.CharField(max_length=100, blank=True, db_index=True)
    title = models.CharField(max_length=200, default='New Chat')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f'{self.title} ({self.user or "anonymous"})'


class ChatMessage(models.Model):
    """Individual message in a chat session."""
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
        ('system', 'System'),
    ]
    FEEDBACK_CHOICES = [
        ('positive', 'Positive'),
        ('negative', 'Negative'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        ChatSession,
        on_delete=models.CASCADE,
        related_name='messages',
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    tokens_used = models.IntegerField(default=0)
    feedback = models.CharField(max_length=10, choices=FEEDBACK_CHOICES, null=True, blank=True)
    action_data = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f'{self.role}: {self.content[:50]}...'
