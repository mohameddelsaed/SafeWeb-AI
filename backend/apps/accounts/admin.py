from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, APIKey, UserSession


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'name', 'role', 'is_active', 'created_at']
    list_filter = ['role', 'is_active', 'is_2fa_enabled']
    search_fields = ['email', 'name']
    ordering = ['-created_at']
    fieldsets = BaseUserAdmin.fieldsets + (  # type: ignore[operator]
        ('SafeWeb Fields', {
            'fields': ('name', 'role', 'company', 'job_title',
                       'is_2fa_enabled', 'last_login_ip'),
        }),
    )


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'name', 'is_active', 'scans_count', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'user__email']


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'ip_address', 'is_active', 'last_activity', 'created_at']
    list_filter = ['is_active']
    search_fields = ['user__email', 'ip_address']
