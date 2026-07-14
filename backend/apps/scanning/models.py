import uuid
from django.db import models
from django.conf import settings


class OrganizationManager(models.Manager):
    def get_queryset(self):
        qs = super().get_queryset()
        try:
            from apps.accounts.middleware import get_current_organization
            org = get_current_organization()
            if org:
                return qs.filter(organization=org)
        except ImportError:
            pass
        return qs

class Target(models.Model):
    """Web property target to be scanned."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='targets'
    )
    domain = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255)
    tags = models.JSONField(default=list, blank=True)
    is_dns_verified = models.BooleanField(default=False)
    consent_timestamp = models.DateTimeField(null=True, blank=True)
    consent_user_id = models.UUIDField(null=True, blank=True)
    current_score = models.IntegerField(default=0)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = OrganizationManager()

    class Meta:
        db_table = 'targets'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.display_name} ({self.domain})'


class Scan(models.Model):
    """Scan job model — tracks a security scan request and its results."""
    SCAN_TYPES = [
        ('website', 'Website'),
        # DEACTIVATED: File/URL threat detection disabled — code preserved
        # ('file', 'File'),
        # ('url', 'URL'),
    ]
    SCAN_STATUSES = [
        ('pending', 'Pending'),
        ('pending_confirmation', 'Pending Confirmation'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    SCAN_DEPTHS = [('shallow', 'Shallow'), ('medium', 'Medium'), ('deep', 'Deep'), ('custom', 'Custom')]

    SCOPE_TYPES = [
        ('single_domain', 'Single Domain'),
        ('wildcard', 'Wildcard Domain'),
        ('wide_scope', 'Wide Scope'),
    ]

    # Phase 18: scan mode choices
    SCAN_MODES = [
        ('standard', 'Standard'),
        ('continuous', 'Continuous'),
        ('hunting', 'Hunting'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='scans',
        null=True,
    )
    target_entity = models.ForeignKey(
        Target,
        on_delete=models.CASCADE,
        related_name='scans',
        null=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scans',
    )
    selected_categories = models.JSONField(default=list, blank=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    target = models.TextField()  # URL, wildcard pattern, or company name
    status = models.CharField(max_length=20, choices=SCAN_STATUSES, default='pending')
    depth = models.CharField(max_length=20, choices=SCAN_DEPTHS, default='medium')
    include_subdomains = models.BooleanField(default=True)

    # Scope type — determines how the target is resolved into scannable domains
    scope_type = models.CharField(
        max_length=20, choices=SCOPE_TYPES, default='single_domain',
    )
    seed_domains = models.JSONField(default=list, blank=True)
    discovered_domains = models.JSONField(default=list, blank=True)

    check_ssl = models.BooleanField(default=True)
    follow_redirects = models.BooleanField(default=True)
    control_external_tools = models.BooleanField(default=True)
    score = models.IntegerField(default=0)  # 0-100 security score
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(default=0)  # seconds
    error_message = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    # File upload (for file scans)
    uploaded_file = models.FileField(upload_to='scan_files/', null=True, blank=True)

    # Recon data (technologies, WAF info, subdomains discovered during pre-scan)
    recon_data = models.JSONField(default=dict, blank=True)

    # Progress tracking
    progress = models.IntegerField(default=0)  # 0-100
    current_phase = models.CharField(max_length=64, blank=True, default='')
    current_tool = models.CharField(max_length=150, blank=True, default='')  # live tool name shown in UI
    phase_timings = models.JSONField(default=dict, blank=True)  # {phase_name: duration_seconds} for ETA
    total_requests = models.IntegerField(default=0)
    pages_crawled = models.IntegerField(default=0)

    # Phase 18: autonomous hunting fields
    mode = models.CharField(
        max_length=20, choices=SCAN_MODES, default='standard',
    )
    next_scan_at = models.DateTimeField(null=True, blank=True)
    parent_scan = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='child_scans',
    )

    # Phase 48: per-tester execution metrics
    tester_results = models.JSONField(default=list, blank=True)

    # Agentic multi-agent orchestration fields
    flow_status = models.CharField(max_length=50, default='initializing')
    task_graph = models.JSONField(default=dict, blank=True)
    engagement_log = models.JSONField(default=list, blank=True)
    cost_meter_usd = models.DecimalField(max_digits=8, decimal_places=4, default=0.0000)
    scope_allowlist = models.JSONField(default=list, blank=True)

    # Incremental-update counter: incremented each time recon_data or tester_results
    # are saved mid-scan so the SSE stream can emit a data_update signal.
    data_version = models.IntegerField(default=0)

    objects = OrganizationManager()

    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.scan_type} scan: {self.target} ({self.status})'

    @property
    def vulnerability_summary(self):
        """Return vulnerability count by severity."""
        from django.db.models import Count
        counts = self.vulnerabilities.values('severity').annotate(count=Count('id'))
        summary = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for item in counts:
            summary[item['severity']] = item['count']
            summary['total'] += item['count']
        return summary


# Canonical vulnerability categories to ensure consistent naming across all tools
VULNERABILITY_CATEGORIES = [
    'SQL Injection',
    'XSS',
    'CSRF',
    'SSRF',
    'XXE',
    'IDOR',
    'Open Redirect',
    'Path Traversal',
    'Command Injection',
    'SSTI',
    'CRLF Injection',
    'Host Header Injection',
    'Clickjacking',
    'Information Disclosure',
    'Authentication Bypass',
    'Authorization Bypass',
    'Broken Access Control',
    'Security Misconfiguration',
    'Sensitive Data Exposure',
    'Insecure Deserialization',
    'Cryptographic Weakness',
    'SSL/TLS Issue',
    'HTTP Security Header',
    'Cookie Security',
    'CORS Misconfiguration',
    'Subdomain Takeover',
    'Secret Exposure',
    'Exposed Git Repository',
    'Exposed Admin Panel',
    'Default Credentials',
    'Nuclei',
    'OOB',
    'Other',
]


class Vulnerability(models.Model):
    """Individual vulnerability finding from a scan."""
    SEVERITIES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    VERIFICATION_STATUS_CHOICES = [
        ('candidate', 'Candidate (Unverified)'),
        ('verified', 'Verified (3/3 Confirmed)'),
        ('unverified', 'Unverified (Replay Failed)'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITIES)
    category = models.CharField(
        max_length=100,
        help_text='Use one of VULNERABILITY_CATEGORIES for consistency.',
    )
    description = models.TextField()
    impact = models.TextField()
    remediation = models.TextField()
    ai_explanation = models.TextField(blank=True, default='')
    ai_remediation = models.TextField(blank=True, default='')
    cwe = models.CharField(max_length=64, blank=True, default='')
    cvss = models.FloatField(default=0.0)
    affected_url = models.CharField(max_length=2048, blank=True, default='')
    tool_name = models.CharField(max_length=100, blank=True, default='')
    evidence = models.TextField(blank=True, default='')
    is_false_positive = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    false_positive_score = models.FloatField(default=0.0)  # 0.0-1.0
    attack_chain = models.CharField(max_length=128, blank=True, default='')
    oob_callback = models.CharField(max_length=255, blank=True, default='')  # Phase 19: OOB callback ID
    exploit_data = models.JSONField(default=dict, blank=True)  # Exploit proof + BB report data
    verification_status = models.CharField(max_length=20, choices=VERIFICATION_STATUS_CHOICES, default='candidate')
    proof_capsule = models.JSONField(default=dict, blank=True, null=True)
    action_id_reference = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-cvss', 'severity']
        verbose_name_plural = 'vulnerabilities'

    def __str__(self):
        return f'{self.severity.upper()}: {self.name}'


class AuthConfig(models.Model):
    """Authentication configuration for authenticated scanning (Phase 21)."""
    AUTH_TYPES = [
        ('form', 'Form Login'),
        ('api', 'API Token'),
        ('cookie', 'Cookie'),
        ('bearer', 'Bearer Token'),
        ('custom', 'Custom Header'),
    ]

    ROLE_CHOICES = [
        ('attacker', 'Attacker'),
        ('victim', 'Victim'),
        ('admin', 'Admin'),
        ('user', 'User'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='auth_configs')
    auth_type = models.CharField(max_length=20, choices=AUTH_TYPES)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='attacker')
    config_data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'auth_configs'

    def __str__(self):
        return f'{self.auth_type} auth for scan {self.scan_id}'


# ── Phase 43: Scheduled & Continuous Scanning ─────────────────────────────

class ScheduledScan(models.Model):
    """Cron-scheduled recurring scan (Phase 43)."""
    SCHEDULE_PRESETS = [
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('custom', 'Custom Cron'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scheduled_scans',
    )
    name = models.CharField(max_length=200)
    scan_config = models.JSONField(default=dict)
    schedule_preset = models.CharField(
        max_length=20, choices=SCHEDULE_PRESETS, default='weekly',
    )
    cron_expr = models.CharField(max_length=100, default='0 2 * * 1')
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    notify_on_new_findings = models.BooleanField(default=True)
    notify_on_ssl_expiry = models.BooleanField(default=True)
    notify_on_asset_changes = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scheduled_scans'
        ordering = ['next_run']

    def __str__(self):
        return f'{self.name} ({self.schedule_preset})'


class AssetMonitorRecord(models.Model):
    """Snapshot of a detected asset change for continuous monitoring (Phase 43)."""
    CHANGE_TYPES = [
        ('new_subdomain', 'New Subdomain'),
        ('removed_subdomain', 'Subdomain Removed'),
        ('ssl_expiring', 'SSL Certificate Expiring'),
        ('ssl_expired', 'SSL Certificate Expired'),
        ('new_port', 'New Open Port'),
        ('closed_port', 'Port Closed'),
        ('tech_added', 'Technology Added'),
        ('tech_removed', 'Technology Removed'),
        ('new_finding', 'New Vulnerability Finding'),
        ('fixed_finding', 'Fixed Vulnerability'),
        ('regressed_finding', 'Regressed Vulnerability'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scheduled_scan = models.ForeignKey(
        ScheduledScan,
        on_delete=models.CASCADE,
        related_name='monitor_records',
        null=True,
        blank=True,
    )
    target = models.CharField(max_length=2048)
    change_type = models.CharField(max_length=50, choices=CHANGE_TYPES)
    detail = models.TextField()
    severity = models.CharField(max_length=20, default='info')
    acknowledged = models.BooleanField(default=False)
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'asset_monitor_records'
        ordering = ['-detected_at']

    def __str__(self):
        return f'{self.change_type}: {self.target}'


# ── End Phase 43 ────────────────────────────────────────────────────────────


class ScanReport(models.Model):
    """Generated reports for scans."""
    FORMATS = [
        ('pdf', 'PDF'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xml', 'XML'),
        ('html', 'HTML'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports')
    format = models.CharField(max_length=10, choices=FORMATS)
    file = models.FileField(upload_to='reports/')
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_reports'
        ordering = ['-generated_at']

    def __str__(self):
        return f'{self.format.upper()} report for {self.scan.target}'


class SharedReport(models.Model):
    """Public read-only link for a scan report (Phase C/F08)."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='shared_reports')
    access_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    password_hash = models.CharField(max_length=128, blank=True, default='', help_text="Optional password protection")
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'shared_reports'
        ordering = ['-created_at']

    def __str__(self):
        return f'Shared Report for {self.scan.target} ({self.id})'


# ── Phase 44: API-First Architecture ─────────────────────────────────────────

class Webhook(models.Model):
    """Webhook endpoint configured to receive scan event notifications (Phase 44)."""
    EVENT_CHOICES = [
        ('scan_started', 'Scan Started'),
        ('finding_detected', 'Finding Detected'),
        ('scan_completed', 'Scan Completed'),
        ('scan_failed', 'Scan Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='webhooks',
    )
    url = models.URLField(max_length=2048)
    secret = models.CharField(max_length=255, blank=True, default='')
    events = models.JSONField(default=list)  # list of event type strings
    is_active = models.BooleanField(default=True)
    max_retries = models.IntegerField(default=3)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'webhooks'
        ordering = ['-created_at']

    def __str__(self):
        return f'Webhook → {self.url}'


class WebhookDelivery(models.Model):
    """Delivery attempt record for a webhook event (Phase 44)."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    webhook = models.ForeignKey(
        Webhook, on_delete=models.CASCADE, related_name='deliveries',
    )
    event_type = models.CharField(max_length=50)
    payload = models.JSONField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    http_status = models.IntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True, default='')
    attempt_count = models.IntegerField(default=0)
    last_attempted_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'webhook_deliveries'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.event_type} → {self.webhook.url} ({self.status})'


class NucleiTemplate(models.Model):
    """Custom Nuclei YAML template uploaded by a user (Phase 44)."""
    SEVERITY_CHOICES = [
        ('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'),
        ('high', 'High'), ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    category = models.CharField(max_length=100, blank=True, default='custom')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    content = models.TextField()  # raw YAML content
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='nuclei_templates',
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'nuclei_templates'
        ordering = ['-created_at']

    def __str__(self):
        return self.name


# ── End Phase 44 ─────────────────────────────────────────────────────────────


# ── Phase 45: Multi-Target & Scope Management ─────────────────────────────────

class ScopeDefinition(models.Model):
    """
    Defines in-scope and out-of-scope patterns for a scanning engagement (Phase 45).
    Supports wildcards (*.example.com), exact domains, and CIDR ranges.
    """
    IMPORT_FORMATS = [
        ('manual', 'Manual'),
        ('hackerone', 'HackerOne'),
        ('bugcrowd', 'Bugcrowd'),
        ('file', 'File Import'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scope_definitions',
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, default='')
    organization = models.CharField(max_length=200, blank=True, default='')
    # Lists of domain/IP/CIDR/path patterns
    in_scope = models.JSONField(default=list)    # [{"type": "domain", "value": "*.example.com"}, ...]
    out_of_scope = models.JSONField(default=list)  # exclusion patterns
    import_format = models.CharField(max_length=20, choices=IMPORT_FORMATS, default='manual')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scope_definitions'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.organization})' if self.organization else self.name


class MultiTargetScan(models.Model):
    """
    Orchestrates scanning of multiple targets under one engagement (Phase 45).
    Creates individual Scan records for each target and tracks consolidated status.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('partial', 'Partially Completed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='multi_target_scans',
    )
    name = models.CharField(max_length=200)
    targets = models.JSONField(default=list)       # ["https://a.com", "https://b.com", ...]
    scope = models.ForeignKey(
        ScopeDefinition,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='multi_scans',
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    scan_depth = models.CharField(max_length=20, default='medium')
    parallel_limit = models.IntegerField(default=3)
    total_targets = models.IntegerField(default=0)
    completed_targets = models.IntegerField(default=0)
    failed_targets = models.IntegerField(default=0)
    sub_scans = models.ManyToManyField(
        Scan,
        blank=True,
        related_name='multi_target_parent',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'multi_target_scans'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.total_targets} targets)'


class DiscoveredAsset(models.Model):
    """
    Tracks all discovered assets per organization for inventory & change detection (Phase 45).
    """
    ASSET_TYPES = [
        ('web_app', 'Web Application'),
        ('api', 'REST/GraphQL API'),
        ('mobile_api', 'Mobile API'),
        ('cdn', 'CDN / Static Asset'),
        ('subdomain', 'Subdomain'),
        ('ip', 'IP Address / Network'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='discovered_assets',
    )
    organization = models.CharField(max_length=200, blank=True, default='')
    url = models.TextField()
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPES, default='web_app')
    tech_stack = models.JSONField(default=list)   # ["Django", "Nginx", ...]
    is_active = models.BooleanField(default=True)
    is_new = models.BooleanField(default=True)   # flag for "new since last scan"
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_scan = models.ForeignKey(
        Scan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='discovered_assets',
    )
    notes = models.TextField(blank=True, default='')

    class Meta:
        db_table = 'discovered_assets'
        ordering = ['-last_seen']
        unique_together = [('user', 'url')]

    def __str__(self):
        return f'{self.asset_type}: {self.url}'


# ── End Phase 45 ─────────────────────────────────────────────────────────────
