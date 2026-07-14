import uuid
from django.db import models


class Category(models.Model):
    """Taxonomy category for learning center content."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=120, unique=True)
    label = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    parent = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='children',
    )
    depth = models.PositiveSmallIntegerField(default=0)
    sort_order = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['sort_order', 'label']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_active']),
            models.Index(fields=['parent', 'is_active']),
        ]

    def __str__(self):
        return self.label


class Tag(models.Model):
    """Cross-cutting tags used for filtering and article discovery."""

    TYPE_CHOICES = [
        ('vuln', 'Vulnerability'),
        ('defense', 'Defense'),
        ('framework', 'Framework'),
        ('protocol', 'Protocol'),
        ('standard', 'Standard'),
        ('industry', 'Industry'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=120, unique=True)
    label = models.CharField(max_length=120)
    tag_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='vuln')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['label']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['tag_type', 'is_active']),
        ]

    def __str__(self):
        return self.label


class Article(models.Model):
    """Learning center articles about cybersecurity topics."""

    CATEGORY_CHOICES = [
        ('injection', 'Injection Attacks'),
        ('xss', 'XSS'),
        ('best_practices', 'Best Practices'),
        ('api_security', 'API Security'),
        ('authentication', 'Authentication'),
        ('security_headers', 'Security Headers'),
        ('access_control', 'Access Control'),
        ('cryptography', 'Cryptography'),
        ('network_security', 'Network Security'),
    ]
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('review', 'Review'),
        ('published', 'Published'),
    ]
    DIFFICULTY_CHOICES = [
        ('foundation', 'Foundation'),
        ('practitioner', 'Practitioner'),
        ('specialist', 'Specialist'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=300)
    slug = models.SlugField(max_length=300, unique=True)
    canonical_slug = models.SlugField(max_length=300, blank=True, null=True)
    excerpt = models.TextField(max_length=500)
    content = models.TextField()
    # Keep legacy single-category field for backward compatibility.
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    categories = models.ManyToManyField(Category, related_name='articles', blank=True)
    tags = models.ManyToManyField(Tag, related_name='articles', blank=True)
    difficulty_level = models.CharField(max_length=20, choices=DIFFICULTY_CHOICES, default='practitioner')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='published')
    author = models.CharField(max_length=100, default='Security Team')
    read_time = models.IntegerField(default=5, help_text='Estimated reading time in minutes')
    source_count = models.PositiveIntegerField(default=0)
    references = models.JSONField(default=list, blank=True)
    cwe_ids = models.JSONField(default=list, blank=True)
    owasp_refs = models.JSONField(default=list, blank=True)
    related_article_ids = models.JSONField(default=list, blank=True)
    image = models.URLField(blank=True, null=True)
    is_published = models.BooleanField(default=True)
    version = models.CharField(max_length=20, default='1.0')
    last_reviewed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_published', 'created_at']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['difficulty_level', 'created_at']),
        ]

    def __str__(self):
        return self.title
