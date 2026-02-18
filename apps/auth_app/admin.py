"""
Admin configuration for auth app.
"""

from django.contrib import admin
from .models import SupabaseUser, RefreshToken, LoginAttempt, Invitation


@admin.register(SupabaseUser)
class SupabaseUserAdmin(admin.ModelAdmin):
    list_display = [
        'email', 'user', 'tenant', 'role', 'is_active',
        'email_confirmed', 'last_login', 'created_at'
    ]
    list_filter = ['role', 'is_active', 'email_confirmed', 'created_at']
    search_fields = ['email', 'user__username', 'supabase_uid']
    readonly_fields = ['supabase_uid', 'created_at', 'updated_at', 'last_login']
    
    fieldsets = (
        ('User Information', {
            'fields': ('supabase_uid', 'user', 'email', 'phone')
        }),
        ('Tenant', {
            'fields': ('tenant', 'role')
        }),
        ('Agent Access', {
            'fields': ('can_access_mark', 'can_access_hr')
        }),
        ('Status', {
            'fields': ('is_active', 'email_confirmed')
        }),
        ('Profile', {
            'fields': ('avatar_url', 'raw_metadata')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_login'),
            'classes': ('collapse',)
        }),
    )


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ['supabase_user', 'is_revoked', 'expires_at', 'created_at']
    list_filter = ['is_revoked', 'created_at']
    readonly_fields = ['created_at']


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['email', 'success', 'ip_address', 'created_at']
    list_filter = ['success', 'created_at']
    search_fields = ['email', 'ip_address']
    readonly_fields = [f.name for f in LoginAttempt._meta.fields]
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ['email', 'tenant', 'role', 'is_used', 'expires_at', 'created_at']
    list_filter = ['role', 'is_used', 'created_at']
    search_fields = ['email', 'tenant__name']
    readonly_fields = ['token', 'created_at', 'used_at']
