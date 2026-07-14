from django.db import models as db_models
from rest_framework import serializers
from .models import SystemAlert, SystemSettings
from apps.accounts.models import User
from apps.scanning.models import Scan


class SystemAlertSerializer(serializers.ModelSerializer):
    type = serializers.CharField(source='severity')
    time = serializers.SerializerMethodField()

    class Meta:
        model = SystemAlert
        fields = ['id', 'title', 'message', 'type', 'is_resolved', 'time', 'created_at']

    def get_time(self, obj):
        from apps.accounts.utils import time_ago
        return time_ago(obj.created_at)


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSettings
        fields = ['key', 'value', 'description', 'updated_at']


class AdminUserSerializer(serializers.ModelSerializer):
    scans = serializers.SerializerMethodField()
    joined = serializers.DateTimeField(source='date_joined', format='%Y-%m-%d')
    last_active = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'status', 'scans', 'joined', 'last_active', 'role']

    def get_scans(self, obj):
        return obj.scans.count()

    def get_last_active(self, obj):
        if obj.last_login:
            from apps.accounts.utils import time_ago
            return time_ago(obj.last_login)
        return 'Never'

    def get_status(self, obj):
        if not obj.is_active:
            return 'suspended'
        if obj.last_login is None:
            return 'inactive'
        return 'active'


class AdminScanSerializer(serializers.ModelSerializer):
    url = serializers.CharField(source='target')
    user = serializers.SerializerMethodField()
    vulnerabilities = serializers.SerializerMethodField()
    severity = serializers.SerializerMethodField()
    started = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = ['id', 'url', 'user', 'status', 'vulnerabilities', 'severity', 'started', 'duration']

    def get_user(self, obj):
        return obj.user.email if obj.user else 'anonymous'

    def get_vulnerabilities(self, obj):
        return obj.vulnerabilities.count()

    def get_severity(self, obj):
        vuln = obj.vulnerabilities.order_by(
            db_models.Case(
                db_models.When(severity='critical', then=0),
                db_models.When(severity='high', then=1),
                db_models.When(severity='medium', then=2),
                db_models.When(severity='low', then=3),
                default=4,
                output_field=db_models.IntegerField(),
            )
        ).first()
        return vuln.severity if vuln else '-'

    def get_started(self, obj):
        if obj.started_at:
            return obj.started_at.strftime('%Y-%m-%d %H:%M')
        return '-'

    def get_duration(self, obj):
        if obj.started_at and obj.completed_at:
            delta = obj.completed_at - obj.started_at
            total_seconds = int(delta.total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f'{minutes}m {seconds}s'
        return '-'


class AdminMLSerializer(serializers.Serializer):
    """Serializes ML model metadata for admin panel."""
    id = serializers.CharField()
    name = serializers.CharField()
    status = serializers.CharField()
    accuracy = serializers.FloatField()
    last_trained = serializers.DateTimeField()
    training_data = serializers.CharField()
    version = serializers.CharField()


class AdminContactSerializer(serializers.ModelSerializer):
    """Serializes contact messages for admin panel."""
    subject_display = serializers.CharField(source='get_subject_display', read_only=True)
    replied_by_name = serializers.SerializerMethodField()

    class Meta:
        from apps.accounts.models import ContactMessage
        model = ContactMessage
        fields = [
            'id', 'name', 'email', 'subject', 'subject_display', 'message',
            'is_read', 'reply', 'replied_at', 'replied_by_name', 'created_at',
        ]
        read_only_fields = ['id', 'name', 'email', 'subject', 'message', 'created_at']

    def get_replied_by_name(self, obj):
        return obj.replied_by.name if obj.replied_by else None


class AdminJobApplicationSerializer(serializers.ModelSerializer):
    """Serializes job applications for admin panel."""
    class Meta:
        from apps.accounts.models import JobApplication
        model = JobApplication
        fields = [
            'id', 'position', 'name', 'email', 'phone',
            'cover_letter', 'resume_url', 'portfolio_url',
            'status', 'admin_notes', 'created_at',
        ]
        read_only_fields = ['id', 'position', 'name', 'email', 'phone',
                            'cover_letter', 'resume_url', 'portfolio_url', 'created_at']
