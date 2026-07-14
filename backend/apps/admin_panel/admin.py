from django.contrib import admin
from .models import SystemAlert, SystemSettings


@admin.register(SystemAlert)
class SystemAlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'is_resolved', 'created_at']
    list_filter = ['severity', 'is_resolved']


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ['key', 'value', 'updated_at']
    search_fields = ['key']
