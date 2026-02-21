"""
Serializers for the tenants app (admin portal + agent proxy).
"""

from rest_framework import serializers
from .models import Tenant, AgentConfig, TenantAPIKey, AgentRequestLog


class TenantSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Tenant
        fields = [
            "tenant_id", "name", "slug", "email", "phone",
            "subscription_type", "subscription_status",
            "subscription_start", "subscription_end",
            "rate_limit_per_minute", "monthly_quota", "current_month_usage",
            "notes", "is_active", "member_count",
            "created_at", "updated_at",
        ]
        read_only_fields = ["tenant_id", "slug", "current_month_usage", "created_at", "updated_at"]

    def get_member_count(self, obj):
        return obj.members.filter(is_active=True).count()


class TenantCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = [
            "name", "email", "phone",
            "subscription_type", "subscription_status",
            "subscription_start", "subscription_end",
            "rate_limit_per_minute", "monthly_quota", "notes",
        ]

    def validate_subscription_type(self, value):
        valid = [c[0] for c in Tenant.SUBSCRIPTION_TYPE_CHOICES]
        if value not in valid:
            raise serializers.ValidationError(f"Must be one of: {valid}")
        return value


class TenantUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = [
            "name", "email", "phone",
            "subscription_type", "subscription_status",
            "subscription_start", "subscription_end",
            "rate_limit_per_minute", "monthly_quota",
            "notes", "is_active",
        ]


class AgentConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentConfig
        fields = [
            "id", "agent_type", "endpoint_url", "api_key",
            "custom_headers", "timeout_seconds", "max_retries",
            "is_enabled", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]
        extra_kwargs = {"api_key": {"write_only": True}}


class TenantAPIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantAPIKey
        fields = [
            "id", "name", "key_prefix", "is_active",
            "expires_at", "usage_count", "last_used_at", "created_at",
        ]
        read_only_fields = fields


class TenantAPIKeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)


class AgentRequestLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True, allow_null=True)

    class Meta:
        model = AgentRequestLog
        fields = [
            "id", "user_email", "agent_type", "status",
            "status_code", "response_time_ms", "error_message",
            "client_ip", "created_at",
        ]
        read_only_fields = fields
