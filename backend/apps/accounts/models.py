import uuid
import secrets
from django.contrib.auth.models import AbstractUser
from django.db import models


class Organization(models.Model):
    """Multi-tenancy isolation boundary."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    plan_tier = models.CharField(
        max_length=20,
        choices=[('free', 'Free'), ('pro', 'Pro'), ('enterprise', 'Enterprise')],
        default='free'
    )
    usage_counters = models.JSONField(default=dict, blank=True)
    owner = models.ForeignKey(
        'User', 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='owned_organizations'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'organizations'

    def __str__(self):
        return self.name


class OrganizationMembership(models.Model):
    """Many-to-Many link between User and Organization."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(
        max_length=20,
        choices=[('owner', 'Owner'), ('admin', 'Admin'), ('member', 'Member')],
        default='member'
    )
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'organization_memberships'
        unique_together = ('user', 'organization')

    def __str__(self):
        return f'{self.user.email} - {self.organization.name} ({self.role})'


class AIConfiguration(models.Model):
    """AI Provider configuration per Organization."""
    PROVIDER_CHOICES = [
        ('openai', 'OpenAI Platform'),
        ('anthropic', 'Anthropic Console'),
        ('gemini', 'Google AI Studio (Gemini)'),
        ('groq', 'Groq Cloud'),
        ('openrouter', 'OpenRouter'),
        ('cerebras', 'Cerebras Cloud'),
        ('mistral', 'Mistral AI La Plateforme'),
        ('together', 'Together AI'),
        ('fireworks', 'Fireworks AI'),
        ('xai', 'xAI API'),
        ('custom', 'Custom Provider'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name='ai_config')
    provider = models.CharField(
        max_length=50,
        choices=PROVIDER_CHOICES,
        default='openai'
    )
    api_key = models.CharField(max_length=255, blank=True, default='')
    model_name = models.CharField(max_length=100, blank=True, default='')
    base_url = models.URLField(blank=True, default='', help_text="For custom providers or specific endpoints")
    temperature = models.FloatField(default=0.7)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def masked_api_key(self):
        if not self.api_key:
            return ""
        if len(self.api_key) <= 8:
            return "********"
        return f"{self.api_key[:3]}...{self.api_key[-4:]}"

    class Meta:
        db_table = 'ai_configurations'

    def __str__(self):
        return f'{self.organization.name} AI Config ({self.provider})'


class User(AbstractUser):
    """Extended user model with security-focused fields."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    role = models.CharField(
        max_length=20,
        choices=[('user', 'User'), ('admin', 'Admin')],
        default='user'
    )
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    company = models.CharField(max_length=255, blank=True, default='')
    job_title = models.CharField(max_length=255, blank=True, default='')
    is_2fa_enabled = models.BooleanField(default=False)
    two_fa_secret = models.CharField(max_length=64, blank=True, default='')
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'username']

    class Meta:
        db_table = 'users'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.email})'

    @property
    def is_admin(self):
        return self.role == 'admin' or self.is_superuser

    @property
    def organization(self):
        org = getattr(self, 'current_organization', None)
        if not org:
            first_mem = self.memberships.first()
            if first_mem:
                org = first_mem.organization
            else:
                org = self.owned_organizations.first()
        return org

    @property
    def plan(self):
        org = self.organization
        return org.plan_tier if org else 'pro'


class APIKey(models.Model):
    """API key for programmatic access."""
    id = models.CharField(max_length=64, primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    key = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    scans_count = models.IntegerField(default=0)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'api_keys'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.id})'

    @staticmethod
    def generate_key():
        """Generate a unique API key."""
        return f'sk_live_{secrets.token_hex(24)}'

    @staticmethod
    def generate_id():
        """Generate a unique API key ID."""
        return f'sk_live_{secrets.token_hex(8)}'


class UserSession(models.Model):
    """Track user sessions for security monitoring."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    token_jti = models.CharField(max_length=255, blank=True, default='')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(default='')
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_sessions'
        ordering = ['-last_activity']

    def __str__(self):
        return f'Session for {self.user.email} from {self.ip_address}'


class ContactMessage(models.Model):
    """Stores contact form submissions."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField()
    subject = models.CharField(
        max_length=30,
        choices=[
            ('general', 'General Inquiry'),
            ('support', 'Technical Support'),
            ('sales', 'Sales & Pricing'),
            ('partnership', 'Partnership Opportunities'),
            ('feedback', 'Feedback & Suggestions'),
        ],
        default='general'
    )
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    reply = models.TextField(blank=True, default='')
    replied_at = models.DateTimeField(null=True, blank=True)
    replied_by = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='replied_contacts',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'contact_messages'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} - {self.get_subject_display()}'


class JobApplication(models.Model):
    """Stores career/job applications."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('reviewed', 'Reviewed'),
        ('shortlisted', 'Shortlisted'),
        ('rejected', 'Rejected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    position = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=30, blank=True, default='')
    cover_letter = models.TextField(blank=True, default='')
    resume_url = models.URLField(max_length=500, blank=True, default='')
    portfolio_url = models.URLField(max_length=500, blank=True, default='')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    admin_notes = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'job_applications'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} — {self.position}'
