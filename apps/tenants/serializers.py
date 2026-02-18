"""
Serializers for the tenants app.
"""

from rest_framework import serializers
from .models import Tenant, AgentConfig, TenantAPIKey, TenantUser, AgentRequestLog


class TenantSerializer(serializers.ModelSerializer):
    """Serializer for Tenant model."""
    
    has_mark_access = serializers.BooleanField(source='has_mark_agent_access', read_only=True)
    has_hr_access = serializers.BooleanField(source='has_hr_agent_access', read_only=True)
    is_subscription_active = serializers.BooleanField(source='is_active', read_only=True)
    
    class Meta:
        model = Tenant
        fields = [
            'tenant_id', 'name', 'slug', 'email', 'phone',
            'subscribed_agents', 'status',
            'has_mark_access', 'has_hr_access', 'is_subscription_active',
            'subscription_start', 'subscription_end',
            'rate_limit_per_minute', 'monthly_quota', 'current_month_usage',
            'allowed_domains', 'created_at', 'updated_at', 'last_activity',
        ]
        read_only_fields = [
            'tenant_id', 'slug', 'current_month_usage', 'last_activity',
            'created_at', 'updated_at'
        ]


class TenantCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a new tenant."""
    
    class Meta:
        model = Tenant
        fields = [
            'name', 'email', 'phone', 'subscribed_agents',
            'subscription_end', 'monthly_quota', 'allowed_domains', 'notes'
        ]
    
    def create(self, validated_data):
        # Set default status based on subscription_end
        if validated_data.get('subscription_end'):
            validated_data['status'] = 'active'
        else:
            validated_data['status'] = 'trial'
        
        return super().create(validated_data)


class TenantUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating tenant information."""
    
    class Meta:
        model = Tenant
        fields = [
            'name', 'email', 'phone', 'subscribed_agents',
            'status', 'subscription_end', 'monthly_quota',
            'allowed_domains', 'notes'
        ]


class AgentConfigSerializer(serializers.ModelSerializer):
    """Serializer for AgentConfig model."""
    
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    
    class Meta:
        model = AgentConfig
        fields = [
            'id', 'tenant', 'tenant_name', 'agent_type', 'endpoint_url',
            'custom_headers', 'timeout_seconds', 'max_retries',
            'webhook_url', 'is_enabled', 'health_status', 'last_health_check',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at', 'health_status', 'last_health_check']


class AgentConfigCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating agent configuration with credentials."""
    
    api_key = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        help_text="API key for the external agent"
    )
    api_secret = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        help_text="API secret for the external agent"
    )
    
    class Meta:
        model = AgentConfig
        fields = [
            'tenant', 'agent_type', 'endpoint_url', 'api_key', 'api_secret',
            'custom_headers', 'timeout_seconds', 'max_retries', 'webhook_url'
        ]


class TenantAPIKeySerializer(serializers.ModelSerializer):
    """Serializer for TenantAPIKey model (without exposing the full key)."""
    
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    is_valid = serializers.BooleanField(source='is_valid', read_only=True)
    
    class Meta:
        model = TenantAPIKey
        fields = [
            'id', 'tenant', 'tenant_name', 'name', 'key_type',
            'key_prefix', 'is_active', 'is_valid',
            'usage_count', 'last_used_at', 'expires_at',
            'created_at', 'revoked_at'
        ]
        read_only_fields = [
            'key_prefix', 'usage_count', 'last_used_at',
            'created_at', 'revoked_at'
        ]


class TenantAPIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating API keys."""
    
    class Meta:
        model = TenantAPIKey
        fields = ['tenant', 'name', 'key_type', 'expires_at', 'allowed_ips']


class TenantAPIKeyResponseSerializer(serializers.ModelSerializer):
    """
    Serializer for returning a newly created API key.
    This includes the full key which is only shown once.
    """
    
    api_key = serializers.CharField(read_only=True, help_text="The full API key (shown only once)")
    
    class Meta:
        model = TenantAPIKey
        fields = [
            'id', 'tenant', 'name', 'key_type', 'key_prefix',
            'api_key', 'expires_at', 'created_at'
        ]


class TenantUserSerializer(serializers.ModelSerializer):
    """Serializer for TenantUser model."""
    
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    
    class Meta:
        model = TenantUser
        fields = [
            'id', 'tenant', 'tenant_name', 'email', 'name', 'role',
            'can_access_mark', 'can_access_hr', 'is_active',
            'created_at', 'updated_at', 'last_login'
        ]
        read_only_fields = ['created_at', 'updated_at', 'last_login']


class AgentRequestLogSerializer(serializers.ModelSerializer):
    """Serializer for AgentRequestLog model."""
    
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    
    class Meta:
        model = AgentRequestLog
        fields = [
            'id', 'tenant', 'tenant_name', 'agent_type', 'request_id',
            'request_method', 'request_path', 'status', 'status_code',
            'response_time_ms', 'client_ip', 'created_at'
        ]


class AgentProxyRequestSerializer(serializers.Serializer):
    """
    Serializer for agent proxy requests.
    This validates incoming requests to the agent proxy endpoint.
    """
    
    message = serializers.CharField(
        required=True,
        help_text="Message to send to the agent"
    )
    session_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Session ID for conversation continuity"
    )
    context = serializers.JSONField(
        required=False,
        default=dict,
        help_text="Additional context for the agent"
    )
    user_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="User ID within the tenant"
    )
    
    def validate(self, data):
        """Additional validation for the request."""
        # Ensure message is not empty
        if not data.get('message', '').strip():
            raise serializers.ValidationError({
                'message': 'Message cannot be empty'
            })
        return data


class AgentProxyResponseSerializer(serializers.Serializer):
    """
    Serializer for agent proxy responses.
    Standardizes the response format from different agent backends.
    """
    
    success = serializers.BooleanField()
    response = serializers.CharField()
    session_id = serializers.CharField(required=False)
    metadata = serializers.JSONField(required=False)
    error = serializers.CharField(required=False)


class TenantAccessCheckSerializer(serializers.Serializer):
    """Serializer for checking tenant access to agents."""
    
    tenant_id = serializers.UUIDField()
    agent_type = serializers.ChoiceField(choices=['mark', 'hr'])
    
    def validate_agent_type(self, value):
        """Validate agent type."""
        if value not in ['mark', 'hr']:
            raise serializers.ValidationError("Agent type must be 'mark' or 'hr'")
        return value


class SubscriptionUpdateSerializer(serializers.Serializer):
    """Serializer for updating tenant subscription."""
    
    subscribed_agents = serializers.ChoiceField(
        choices=['mark', 'hr', 'both'],
        help_text="New subscription level"
    )
    subscription_end = serializers.DateTimeField(
        required=False,
        allow_null=True,
        help_text="New subscription end date"
    )
    monthly_quota = serializers.IntegerField(
        required=False,
        min_value=1,
        help_text="New monthly quota"
    )
