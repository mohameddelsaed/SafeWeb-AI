import re
from datetime import timedelta
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import User, APIKey, UserSession, ContactMessage


class RegisterSerializer(serializers.Serializer):
    """Registration serializer matching frontend validation rules."""
    name = serializers.CharField(max_length=255)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('A user with this email already exists.')
        return value.lower()

    def validate_password(self, value):
        # Must match frontend validatePassword(): min 8, uppercase, lowercase, number, special
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters.')
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError('Password must contain at least one number.')
        if not re.search(r'[!@#$%^&*]', value):
            raise serializers.ValidationError('Password must contain at least one special character (!@#$%^&*).')
        return value

    def validate(self, attrs):  # noqa
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User(
            email=validated_data['email'],
            name=validated_data['name'],
            username=validated_data['email'],  # Use email as username
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    """Login serializer."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    remember_me = serializers.BooleanField(default=False, required=False)

    def validate(self, attrs):  # noqa
        email = attrs.get('email', '').lower()
        password = attrs.get('password')

        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError({'detail': 'Invalid email or password.'})
        if not user.is_active:
            raise serializers.ValidationError({'detail': 'This account has been deactivated.'})

        attrs['user'] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """User serializer for responses."""
    has_targets = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'name', 'role', 'avatar',
            'company', 'job_title', 'plan', 'is_2fa_enabled',
            'created_at', 'last_login', 'has_targets',
        ]
        read_only_fields = ['id', 'email', 'role', 'created_at', 'last_login']

    def get_has_targets(self, obj):
        from apps.scanning.models import Target
        return Target.objects.filter(organization__memberships__user=obj).exists() or \
               Target.objects.filter(organization__owner=obj).exists()


class ProfileSerializer(serializers.ModelSerializer):
    """Profile serializer with stats and subscription."""
    stats = serializers.SerializerMethodField()
    subscription = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    two_factor_enabled = serializers.BooleanField(source='is_2fa_enabled', read_only=True)
    has_targets = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'name', 'role', 'avatar',
            'company', 'job_title', 'plan', 'two_factor_enabled',
            'created_at', 'last_login', 'stats', 'subscription', 'has_targets',
        ]
        read_only_fields = ['id', 'email', 'role', 'created_at', 'last_login']

    def get_has_targets(self, obj):
        from apps.scanning.models import Target
        return Target.objects.filter(organization__memberships__user=obj).exists() or \
               Target.objects.filter(organization__owner=obj).exists()

    def get_role(self, obj):
        return 'admin' if obj.is_admin else obj.role

    def get_stats(self, obj):
        from apps.scanning.models import Scan, Vulnerability
        total_scans = Scan.objects.filter(user=obj).count()
        vulnerabilities_found = Vulnerability.objects.filter(scan__user=obj).count()
        issues_fixed = Vulnerability.objects.filter(
            scan__user=obj, is_resolved=True
        ).count() if hasattr(Vulnerability, 'is_resolved') else 0
        return {
            'totalScans': total_scans,
            'vulnerabilitiesFound': vulnerabilities_found,
            'issuesFixed': issues_fixed,
        }

    def get_subscription(self, obj):
        plan_details = {
            'free': {'scansLimit': 10, 'amount': '$0.00'},
            'pro': {'scansLimit': 'Unlimited', 'amount': '$49.00'},
            'enterprise': {'scansLimit': 'Unlimited', 'amount': '$199.00'},
        }
        plan = plan_details.get(obj.plan, plan_details['free'])
        from apps.scanning.models import Scan
        scans_used = Scan.objects.filter(user=obj).count()
        return {
            'plan': obj.plan.capitalize(),
            'status': 'active',
            'scansUsed': scans_used,
            'scansLimit': plan['scansLimit'],
            'billingCycle': 'Monthly',
            'nextBilling': (obj.date_joined + timedelta(days=((timezone.now() - obj.date_joined).days // 30 + 1) * 30)).strftime('%Y-%m-%d') if obj.plan != 'free' else None,
            'amount': plan['amount'],
        }


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for profile updates."""

    class Meta:
        model = User
        fields = ['name', 'company', 'job_title']


class ChangePasswordSerializer(serializers.Serializer):
    """Change password serializer."""
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Current password is incorrect.')
        return value

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters.')
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError('Password must contain at least one number.')
        if not re.search(r'[!@#$%^&*]', value):
            raise serializers.ValidationError('Password must contain at least one special character.')
        return value

    def validate(self, attrs):  # noqa
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    """Forgot password serializer."""
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    """Reset password serializer."""
    email = serializers.EmailField()
    token = serializers.CharField()
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):  # noqa
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
        return attrs


class APIKeySerializer(serializers.ModelSerializer):
    """API Key serializer."""
    created = serializers.DateTimeField(source='created_at', format='%Y-%m-%d')  # type: ignore[arg-type]
    last_used = serializers.SerializerMethodField()
    scans = serializers.IntegerField(source='scans_count')
    is_active = serializers.BooleanField()

    class Meta:
        model = APIKey
        fields = ['id', 'name', 'created', 'last_used', 'scans', 'is_active']

    def get_last_used(self, obj):
        if not obj.last_used_at:
            return 'Never'
        from apps.accounts.utils import time_ago
        return time_ago(obj.last_used_at)


class APIKeyCreateSerializer(serializers.Serializer):
    """Serializer for creating API keys."""
    name = serializers.CharField(max_length=100)


class SessionSerializer(serializers.ModelSerializer):
    """User session serializer."""
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'user_agent', 'last_activity', 'is_active', 'is_current']

    def get_is_current(self, obj):
        request = self.context.get('request')
        if not request:
            return False
        # Simple heuristic: match by IP
        client_ip = self._get_client_ip(request)
        return obj.ip_address == client_ip and obj.is_active

    def _get_client_ip(self, request):
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '127.0.0.1')


class TwoFactorEnableSerializer(serializers.Serializer):
    """No input needed — generates secret."""
    pass


class TwoFactorVerifySerializer(serializers.Serializer):
    """Verify 2FA code."""
    code = serializers.CharField(max_length=6, min_length=6)


class ContactMessageSerializer(serializers.ModelSerializer):
    """Serializer for contact form submissions."""
    class Meta:
        model = ContactMessage
        fields = ['id', 'name', 'email', 'subject', 'message', 'created_at']
        read_only_fields = ['id', 'created_at']


class AIConfigurationSerializer(serializers.ModelSerializer):
    """Serializer for AI Configuration, masking the API key."""
    api_key = serializers.SerializerMethodField()

    class Meta:
        from .models import AIConfiguration
        model = AIConfiguration
        fields = ['id', 'provider', 'model_name', 'api_key']

    def get_api_key(self, obj):
        key = getattr(obj, 'api_key', '')
        if not key:
            return None
        # Return only last 4 characters, e.g., sk-...1234
        if len(key) > 4:
            return f"sk-...{key[-4:]}"
        return "****"
