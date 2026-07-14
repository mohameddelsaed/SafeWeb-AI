from django.contrib import admin
from .models import Scan, Vulnerability, ScanReport, AuthConfig


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'scan_type', 'target', 'status', 'score', 'created_at']
    list_filter = ['scan_type', 'status', 'depth']
    search_fields = ['target', 'user__email']
    readonly_fields = ['id', 'created_at']


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['name', 'severity', 'category', 'cvss', 'verified', 'scan', 'created_at']
    list_filter = ['severity', 'category', 'verified']
    search_fields = ['name', 'cwe']
    readonly_fields = ['exploit_data']


@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ['scan', 'format', 'generated_at']
    list_filter = ['format']


@admin.register(AuthConfig)
class AuthConfigAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'auth_type', 'role', 'created_at']
    list_filter = ['auth_type', 'role']
    search_fields = ['scan__target']
