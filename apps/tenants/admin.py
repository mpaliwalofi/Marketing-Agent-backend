"""
Django admin configuration for the tenants app.
"""

from django.contrib import admin
from .models import Tenant, AgentConfig, TenantAPIKey, AgentRequestLog


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = [
        "name", "slug", "email", "subscription_type", "subscription_status",
        "current_month_usage", "is_active", "created_at",
    ]
    list_filter = ["subscription_status", "subscription_type", "is_active"]
    search_fields = ["name", "email", "slug"]
    readonly_fields = ["tenant_id", "slug", "current_month_usage", "created_at", "updated_at"]

    fieldsets = (
        ("Organisation", {"fields": ("tenant_id", "name", "slug", "email", "phone")}),
        ("Subscription", {
            "fields": (
                "subscription_type", "subscription_status",
                "subscription_start", "subscription_end",
            )
        }),
        ("Quotas", {"fields": ("rate_limit_per_minute", "monthly_quota", "current_month_usage")}),
        ("Meta", {"fields": ("notes", "is_active", "created_at", "updated_at"), "classes": ("collapse",)}),
    )


@admin.register(AgentConfig)
class AgentConfigAdmin(admin.ModelAdmin):
    list_display = ["tenant", "agent_type", "endpoint_url", "is_enabled", "created_at"]
    list_filter = ["agent_type", "is_enabled"]
    search_fields = ["tenant__name", "endpoint_url"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(TenantAPIKey)
class TenantAPIKeyAdmin(admin.ModelAdmin):
    list_display = ["name", "tenant", "key_prefix", "is_active", "usage_count", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["tenant__name", "name", "key_prefix"]
    readonly_fields = ["id", "key_prefix", "key_hash", "usage_count", "last_used_at", "created_at"]


@admin.register(AgentRequestLog)
class AgentRequestLogAdmin(admin.ModelAdmin):
    list_display = ["tenant", "user", "agent_type", "status", "status_code", "response_time_ms", "created_at"]
    list_filter = ["agent_type", "status"]
    search_fields = ["tenant__name"]
    readonly_fields = [f.name for f in AgentRequestLog._meta.fields]
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
