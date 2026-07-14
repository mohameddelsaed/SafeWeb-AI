from rest_framework import serializers
from .models import (
    Scan, Vulnerability, Webhook, WebhookDelivery,
    NucleiTemplate, ScopeDefinition, MultiTargetScan, DiscoveredAsset,
    ScheduledScan, AssetMonitorRecord, AuthConfig, Target,
    SharedReport,
)

class TargetSerializer(serializers.ModelSerializer):
    """Serializer for web targets."""
    class Meta:
        model = Target
        fields = [
            'id', 'organization', 'domain', 'display_name', 'tags',
            'is_dns_verified', 'consent_timestamp', 'current_score',
            'last_scanned_at', 'created_at'
        ]
        read_only_fields = ['id', 'organization', 'is_dns_verified', 'consent_timestamp', 'current_score', 'last_scanned_at', 'created_at']

    def validate_domain(self, value):
        import ipaddress
        from urllib.parse import urlparse
        
        domain = value.strip().lower()
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc.split(':')[0]
            
        # Basic blocklist
        if domain in ['localhost', '169.254.169.254', 'metadata.google.internal']:
            raise serializers.ValidationError("Local or private network targets are not permitted.")
            
        try:
            ip = ipaddress.ip_address(domain)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise serializers.ValidationError("Private IP addresses are not permitted.")
        except ValueError:
            pass
            
        return domain


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for vulnerability details."""
    affected_url = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'name', 'severity', 'category', 'description',
            'impact', 'remediation', 'ai_explanation', 'ai_remediation', 'cwe', 'cvss', 'affected_url',
            'evidence', 'is_false_positive', 'verified',
            'false_positive_score', 'attack_chain', 'oob_callback',
            'exploit_data', 'tool_name',
        ]


class ScanCreateSerializer(serializers.Serializer):
    """Serializer for creating a new scan with scope type support."""
    target = serializers.CharField(max_length=500)
    scope_type = serializers.ChoiceField(
        choices=['single_domain', 'wildcard', 'wide_scope'],
        default='single_domain',
    )
    seed_domains = serializers.ListField(
        child=serializers.CharField(max_length=253),
        required=False, default=list,
    )
    scan_depth = serializers.ChoiceField(
        choices=['shallow', 'medium', 'deep', 'custom'],
        default='medium',
    )
    check_ssl = serializers.BooleanField(default=True)
    follow_redirects = serializers.BooleanField(default=True)
    control_external_tools = serializers.BooleanField(default=True)
    selected_categories = serializers.ListField(
        child=serializers.CharField(),
        required=False, default=list,
    )

    def validate(self, attrs):
        scope_type = attrs.get('scope_type', 'single_domain')
        target = attrs.get('target', '').strip()

        # SSRF Protection
        lower_target = target.lower()
        if 'localhost' in lower_target or '169.254.169.254' in lower_target or 'metadata.google.internal' in lower_target or '127.0.0.1' in lower_target:
            raise serializers.ValidationError({'target': 'Local or private network targets are not permitted.'})

        if scope_type == 'single_domain':
            # Must be a valid URL
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'
                attrs['target'] = target
            from django.core.validators import URLValidator
            try:
                URLValidator()(target)
            except Exception:
                raise serializers.ValidationError({'target': 'Please enter a valid URL for single domain scans.'})

        elif scope_type == 'wildcard':
            # Must contain wildcard pattern like *.example.com
            if not target.startswith('*.'):
                raise serializers.ValidationError({'target': 'Wildcard scope requires a pattern like *.example.com'})

        elif scope_type == 'wide_scope':
            # Must have a non-empty company/org name
            if len(target) < 2:
                raise serializers.ValidationError({'target': 'Please enter a company or organization name.'})

        return attrs


class ScanURLCreateSerializer(serializers.Serializer):
    """Serializer for URL phishing scan."""
    url = serializers.URLField()


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed scan result — matches ScanResults.tsx structure."""
    type = serializers.CharField(source='scan_type')
    start_time = serializers.DateTimeField(source='started_at')
    end_time = serializers.DateTimeField(source='completed_at')
    summary = serializers.SerializerMethodField()
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    scan_options = serializers.SerializerMethodField()
    ml_result = serializers.SerializerMethodField()
    child_scans = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'target', 'type', 'status', 'start_time', 'end_time',
            'duration', 'score', 'summary', 'vulnerabilities', 'scan_options',
            'ml_result', 'progress', 'current_phase', 'current_tool', 'phase_timings',
            'total_requests', 'pages_crawled', 'recon_data', 'tester_results', 'mode',
            'scope_type', 'seed_domains', 'discovered_domains', 'child_scans',
            'data_version', 'flow_status', 'cost_meter_usd', 'engagement_log', 'task_graph',
        ]

    def get_summary(self, obj):
        return obj.vulnerability_summary

    def get_scan_options(self, obj):
        return {
            'depth': obj.depth,
            'includeSubdomains': obj.include_subdomains,
            'checkSsl': obj.check_ssl,
            'controlExternalTools': obj.control_external_tools,
        }

    def get_child_scans(self, obj):
        """Return child scan summaries for wildcard/wide_scope parent scans."""
        children = obj.child_scans.all()
        if not children.exists():
            return []
        return [
            {
                'id': str(child.id),
                'target': child.target,
                'status': child.status,
                'score': child.score,
                'vulnerabilitySummary': child.vulnerability_summary,
            }
            for child in children.order_by('created_at')
        ]

    def get_ml_result(self, obj):
        # DEACTIVATED: ML file/URL predictions disabled — returning None
        # Original code preserved below:
        # try:
        #     result = obj.ml_predictions.order_by('-created_at').first()
        #     if result:
        #         return {
        #             'prediction': result.prediction,
        #             'confidence': result.confidence,
        #             'modelUsed': result.model.name if result.model else 'rule-based',
        #         }
        # except Exception:
        #     pass
        return None


class SharedReportSerializer(serializers.ModelSerializer):
    """Serializer for SharedReport."""
    url = serializers.SerializerMethodField()

    class Meta:
        model = SharedReport
        fields = ['id', 'scan', 'access_token', 'password_hash', 'expires_at', 'created_at', 'url']
        read_only_fields = ['id', 'access_token', 'created_at', 'url']
        extra_kwargs = {'password_hash': {'write_only': True}}

    def get_url(self, obj):
        request = self.context.get('request')
        if request:
            # Point to a potential frontend route or an API endpoint, here returning token
            return request.build_absolute_uri(f'/public/report/{obj.access_token}/')
        return f'/public/report/{obj.access_token}/'


class ScanListSerializer(serializers.ModelSerializer):
    """Scan list item — matches ScanHistory.tsx structure."""
    type = serializers.CharField(source='get_scan_type_display')
    date = serializers.DateTimeField(source='created_at')
    vulnerabilities = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'target', 'type', 'status', 'date',
            'duration', 'score', 'vulnerabilities', 'scope_type',
        ]

    def get_vulnerabilities(self, obj):
        return obj.vulnerability_summary


# ── Phase 44: API-First Architecture serializers ───────────────────────────

class ScanFullCreateSerializer(serializers.Serializer):
    """Full-config scan creation — extends base with profile, auth, scope."""
    # Backward-compatible aliasing: frontend/tests commonly send `url`, while
    # some internal callers still use `target`.
    url = serializers.URLField(required=False)
    target = serializers.CharField(max_length=500, required=False)
    scope_type = serializers.ChoiceField(
        choices=['single_domain', 'wildcard', 'wide_scope'],
        default='single_domain',
    )
    seed_domains = serializers.ListField(
        child=serializers.CharField(max_length=253),
        required=False, default=list,
    )
    include_subdomains = serializers.BooleanField(default=True)
    scan_depth = serializers.ChoiceField(
        choices=['shallow', 'medium', 'deep', 'custom'], default='medium',
    )
    check_ssl = serializers.BooleanField(default=True)
    follow_redirects = serializers.BooleanField(default=True)
    control_external_tools = serializers.BooleanField(default=True)
    selected_categories = serializers.ListField(
        child=serializers.CharField(),
        required=False, default=list,
    )
    profile = serializers.CharField(max_length=64, required=False, allow_blank=True, default='')
    auth_config = serializers.DictField(required=False, default=dict)
    scope = serializers.ListField(
        child=serializers.CharField(), required=False, default=list,
    )
    scan_mode = serializers.ChoiceField(
        choices=['standard', 'continuous', 'hunting'], default='standard',
    )

    def validate(self, attrs):
        url = attrs.get('url')
        target = attrs.get('target')
        if not url and not target:
            raise serializers.ValidationError({'url': 'This field is required.'})

        normalized = url or target
        attrs['url'] = normalized
        attrs['target'] = normalized
        return attrs


class FindingFilterSerializer(serializers.Serializer):
    """Query params for paginated findings endpoint."""
    severity = serializers.MultipleChoiceField(
        choices=['critical', 'high', 'medium', 'low', 'info'],
        required=False,
    )
    category = serializers.CharField(required=False, allow_blank=True)
    verified = serializers.BooleanField(required=False)
    search = serializers.CharField(required=False, allow_blank=True)


class WebhookSerializer(serializers.ModelSerializer):
    """Webhook CRUD serializer."""
    class Meta:
        model = Webhook
        fields = [
            'id', 'url', 'secret', 'events', 'is_active',
            'max_retries', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {'secret': {'write_only': True}}

    def validate_events(self, value):
        valid = {'scan_started', 'finding_detected', 'scan_completed', 'scan_failed'}
        for ev in value:
            if ev not in valid:
                raise serializers.ValidationError(f'Unknown event type: {ev!r}')
        return value


class WebhookDeliverySerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookDelivery
        fields = [
            'id', 'webhook', 'event_type', 'status', 'http_status',
            'attempt_count', 'last_attempted_at', 'delivered_at', 'created_at',
        ]
        read_only_fields = fields


class NucleiTemplateSerializer(serializers.ModelSerializer):
    """Custom Nuclei template serializer."""
    uploaded_by = serializers.SerializerMethodField()

    class Meta:
        model = NucleiTemplate
        fields = [
            'id', 'name', 'description', 'category', 'severity',
            'content', 'uploaded_by', 'is_active', 'created_at',
        ]
        read_only_fields = ['id', 'uploaded_by', 'created_at']

    def get_uploaded_by(self, obj):
        if obj.uploaded_by:
            return obj.uploaded_by.email if hasattr(obj.uploaded_by, 'email') else str(obj.uploaded_by)
        return None


class ScanCompareOutputSerializer(serializers.Serializer):
    """Output of comparing two scans."""
    scan_a = serializers.UUIDField()
    scan_b = serializers.UUIDField()
    new_findings = serializers.IntegerField()
    fixed_findings = serializers.IntegerField()
    recurring_findings = serializers.IntegerField()
    severity_changes = serializers.IntegerField()
    regressions = serializers.IntegerField()
    baseline_total = serializers.IntegerField()
    current_total = serializers.IntegerField()
    delta = serializers.IntegerField()
    improved = serializers.BooleanField()
    new_findings_detail = VulnerabilitySerializer(many=True)
    fixed_findings_detail = VulnerabilitySerializer(many=True)


class ScanProfileOutputSerializer(serializers.Serializer):
    """Represents a built-in or custom scan profile."""
    id = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()
    depth = serializers.CharField()
    stealth_level = serializers.CharField()
    max_urls = serializers.IntegerField()
    timeout = serializers.IntegerField()
    enabled_testers = serializers.ListField(child=serializers.CharField())
    tags = serializers.ListField(child=serializers.CharField())


# ── Phase 45: Multi-Target & Scope Management ─────────────────────────────────

class ScopeDefinitionSerializer(serializers.ModelSerializer):
    """Serializer for ScopeDefinition model."""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = ScopeDefinition
        fields = [
            'id', 'user', 'name', 'description', 'organization',
            'in_scope', 'out_of_scope', 'import_format', 'is_active',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class MultiTargetScanSerializer(serializers.ModelSerializer):
    """Serializer for MultiTargetScan model."""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    scope_name = serializers.CharField(source='scope.name', read_only=True, default=None)

    class Meta:
        model = MultiTargetScan
        fields = [
            'id', 'user', 'name', 'targets', 'scope', 'scope_name',
            'status', 'scan_depth', 'parallel_limit',
            'total_targets', 'completed_targets', 'failed_targets',
            'created_at', 'completed_at',
        ]
        read_only_fields = [
            'id', 'status', 'total_targets', 'completed_targets',
            'failed_targets', 'created_at', 'completed_at',
        ]


class DiscoveredAssetSerializer(serializers.ModelSerializer):
    """Serializer for DiscoveredAsset model."""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = DiscoveredAsset
        fields = [
            'id', 'user', 'organization', 'url', 'asset_type', 'tech_stack',
            'is_active', 'is_new', 'first_seen', 'last_seen', 'last_scan', 'notes',
        ]
        read_only_fields = ['id', 'first_seen', 'last_seen']


class ScopeImportSerializer(serializers.Serializer):
    """Input payload for importing a scope from HackerOne or Bugcrowd."""
    PLATFORM_CHOICES = ['hackerone', 'bugcrowd', 'text']
    name = serializers.CharField(max_length=200)
    organization = serializers.CharField(max_length=200, required=False, default='')
    platform = serializers.ChoiceField(choices=PLATFORM_CHOICES)
    raw_data = serializers.JSONField(required=False, default=dict)
    raw_text = serializers.CharField(required=False, default='', allow_blank=True)


class ScopeValidateSerializer(serializers.Serializer):
    """Input payload for validating a single target against a scope."""
    url = serializers.CharField(max_length=2048)


# ── Phase 43+: Scheduled Scans & Asset Monitoring ───────────────────────────

class ScheduledScanSerializer(serializers.ModelSerializer):
    """Full CRUD serializer for scheduled recurring scans."""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = ScheduledScan
        fields = [
            'id', 'user', 'name', 'scan_config', 'schedule_preset',
            'cron_expr', 'last_run', 'next_run', 'is_active',
            'notify_on_new_findings', 'notify_on_ssl_expiry',
            'notify_on_asset_changes', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'last_run', 'created_at', 'updated_at']


class AssetMonitorRecordSerializer(serializers.ModelSerializer):
    """Read-only serializer for asset change records."""

    class Meta:
        model = AssetMonitorRecord
        fields = [
            'id', 'target', 'change_type', 'detail', 'severity',
            'acknowledged', 'detected_at',
        ]
        read_only_fields = ['id', 'detected_at']


class AuthConfigSerializer(serializers.ModelSerializer):
    """Authentication config for authenticated scans."""

    class Meta:
        model = AuthConfig
        fields = ['id', 'scan', 'auth_type', 'role', 'config_data', 'created_at']
        read_only_fields = ['id', 'created_at']
