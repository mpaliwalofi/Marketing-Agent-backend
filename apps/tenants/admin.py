"""
Admin configuration for tenants app.
"""

from django.contrib import admin
from .models import Tenant, AgentConfig, TenantAPIKey, TenantUser, AgentRequestLog


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'slug', 'email', 'subscribed_agents', 'status',
        'is_active_display', 'current_month_usage', 'created_at'
    ]
    list_filter = ['status', 'subscribed_agents', 'created_at']
    search_fields = ['name', 'email', 'slug', 'tenant_id']
    readonly_fields = ['tenant_id', 'slug', 'created_at', 'updated_at', 'last_activity']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('tenant_id', 'name', 'slug', 'email', 'phone')
        }),
        ('Subscription', {
            'fields': ('subscribed_agents', 'status', 'subscription_start', 'subscription_end')
        }),
        ('Quotas & Limits', {
            'fields': ('rate_limit_per_minute', 'monthly_quota', 'current_month_usage')
        }),
        ('Security', {
            'fields': ('allowed_domains', 'ip_whitelist'),
            'classes': ('collapse',)
        }),
        ('Billing', {
            'fields': ('billing_email', 'stripe_customer_id'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('notes', 'created_at', 'updated_at', 'last_activity'),
            'classes': ('collapse',)
        }),
    )
    
    def is_active_display(self, obj):
        """Display subscription status with icon."""
        if obj.is_active:
            return '✅ Active'
        return f'❌ {obj.status.title()}'
    is_active_display.short_description = 'Subscription'


@admin.register(AgentConfig)
class AgentConfigAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'agent_type', 'endpoint_url', 'is_enabled', 'health_status', 'last_health_check']
    list_filter = ['agent_type', 'is_enabled', 'health_status']
    search_fields = ['tenant__name', 'endpoint_url']
    readonly_fields = ['created_at', 'updated_at', 'last_health_check']
    
    fieldsets = (
        ('Basic', {
            'fields': ('tenant', 'agent_type', 'endpoint_url', 'is_enabled')
        }),
        ('Authentication', {
            'fields': ('api_key', 'api_secret', 'custom_headers'),
            'classes': ('collapse',),
            'description': 'API credentials are stored encrypted'
        }),
        ('Configuration', {
            'fields': ('timeout_seconds', 'max_retries', 'webhook_url')
        }),
        ('Health Status', {
            'fields': ('health_status', 'last_health_check'),
            'classes': ('collapse',)
        }),
    )


@admin.register(TenantAPIKey)
class TenantAPIKeyAdmin(admin.ModelAdmin):
    list_display = ['name', 'tenant', 'key_type', 'key_prefix', 'is_active', 'usage_count', 'created_at']
    list_filter = ['key_type', 'is_active', 'created_at']
    search_fields = ['tenant__name', 'name', 'key_prefix']
    readonly_fields = ['id', 'key_prefix', 'key_hash', 'usage_count', 'last_used_at', 'created_at', 'revoked_at']
    
    fieldsets = (
        ('Key Information', {
            'fields': ('id', 'tenant', 'name', 'key_type', 'key_prefix')
        }),
        ('Security', {
            'fields': ('key_hash', 'allowed_ips'),
            'classes': ('collapse',),
            'description': 'The full API key is only shown once when created'
        }),
        ('Usage', {
            'fields': ('usage_count', 'last_used_at')
        }),
        ('Status', {
            'fields': ('is_active', 'expires_at', 'revoked_at', 'revoked_reason')
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )


@admin.register(TenantUser)
class TenantUserAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'tenant', 'role', 'is_active', 'created_at']
    list_filter = ['role', 'is_active', 'created_at']
    search_fields = ['name', 'email', 'tenant__name']


@admin.register(AgentRequestLog)
class AgentRequestLogAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'agent_type', 'status', 'status_code', 'response_time_ms', 'created_at']
    list_filter = ['agent_type', 'status', 'created_at']
    search_fields = ['tenant__name', 'request_id']
    readonly_fields = [f.name for f in AgentRequestLog._meta.fields]
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
