"""
Views for tenant management and agent proxying.
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from django.conf import settings
from django.utils import timezone
import logging

from .models import Tenant, AgentConfig, TenantAPIKey, TenantUser, AgentRequestLog
from .serializers import (
    TenantSerializer, TenantCreateSerializer, TenantUpdateSerializer,
    AgentConfigSerializer, AgentConfigCreateSerializer,
    TenantAPIKeySerializer, TenantAPIKeyCreateSerializer, TenantAPIKeyResponseSerializer,
    TenantUserSerializer, AgentRequestLogSerializer,
    AgentProxyRequestSerializer, AgentProxyResponseSerializer,
    SubscriptionUpdateSerializer
)
from .services import TenantService, AgentProxyService, TenantRateLimiter
from .permissions import IsTenantAdmin, HasTenantAccess, HasAgentAccess
from .authentication import TenantAPIKeyAuthentication

logger = logging.getLogger(__name__)


# =============================================================================
# Tenant Management Views
# =============================================================================

class TenantListCreateView(APIView):
    """List all tenants or create a new tenant."""
    
    def get(self, request):
        """List all tenants."""
        tenants = Tenant.objects.all().order_by('-created_at')
        
        # Filter by status if provided
        status_filter = request.query_params.get('status')
        if status_filter:
            tenants = tenants.filter(status=status_filter)
        
        serializer = TenantSerializer(tenants, many=True)
        return Response({
            'success': True,
            'count': len(serializer.data),
            'tenants': serializer.data
        })
    
    def post(self, request):
        """Create a new tenant."""
        serializer = TenantCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        tenant = serializer.save()
        
        return Response({
            'success': True,
            'message': 'Tenant created successfully',
            'tenant': TenantSerializer(tenant).data
        }, status=status.HTTP_201_CREATED)


class TenantDetailView(APIView):
    """Get, update, or delete a specific tenant."""
    
    def get(self, request, tenant_id):
        """Get tenant details."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = TenantSerializer(tenant)
        
        # Include agent configs
        agent_configs = AgentConfig.objects.filter(tenant=tenant)
        configs_serializer = AgentConfigSerializer(agent_configs, many=True)
        
        return Response({
            'success': True,
            'tenant': serializer.data,
            'agent_configs': configs_serializer.data
        })
    
    def put(self, request, tenant_id):
        """Update tenant information."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = TenantUpdateSerializer(tenant, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        
        return Response({
            'success': True,
            'message': 'Tenant updated successfully',
            'tenant': TenantSerializer(tenant).data
        })
    
    def delete(self, request, tenant_id):
        """Delete a tenant."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        tenant.delete()
        
        return Response({
            'success': True,
            'message': 'Tenant deleted successfully'
        })


# =============================================================================
# Agent Configuration Views
# =============================================================================

class AgentConfigListCreateView(APIView):
    """List or create agent configurations for a tenant."""
    
    def get(self, request, tenant_id):
        """List all agent configurations for a tenant."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        configs = AgentConfig.objects.filter(tenant=tenant)
        serializer = AgentConfigSerializer(configs, many=True)
        
        return Response({
            'success': True,
            'configs': serializer.data
        })
    
    def post(self, request, tenant_id):
        """Create a new agent configuration."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        data = request.data.copy()
        data['tenant'] = tenant_id
        
        serializer = AgentConfigCreateSerializer(data=data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        config = serializer.save()
        
        return Response({
            'success': True,
            'message': 'Agent configuration created',
            'config': AgentConfigSerializer(config).data
        }, status=status.HTTP_201_CREATED)


class AgentConfigDetailView(APIView):
    """Get, update, or delete a specific agent configuration."""
    
    def get(self, request, tenant_id, config_id):
        """Get agent configuration details."""
        try:
            config = AgentConfig.objects.get(id=config_id, tenant_id=tenant_id)
        except AgentConfig.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Configuration not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AgentConfigSerializer(config)
        return Response({
            'success': True,
            'config': serializer.data
        })
    
    def put(self, request, tenant_id, config_id):
        """Update agent configuration."""
        try:
            config = AgentConfig.objects.get(id=config_id, tenant_id=tenant_id)
        except AgentConfig.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Configuration not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AgentConfigSerializer(config, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        
        return Response({
            'success': True,
            'message': 'Configuration updated',
            'config': serializer.data
        })
    
    def delete(self, request, tenant_id, config_id):
        """Delete agent configuration."""
        try:
            config = AgentConfig.objects.get(id=config_id, tenant_id=tenant_id)
        except AgentConfig.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Configuration not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        config.delete()
        
        return Response({
            'success': True,
            'message': 'Configuration deleted'
        })


class AgentHealthCheckView(APIView):
    """Perform health check on an agent."""
    
    def get(self, request, tenant_id, agent_type):
        """Check agent health."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        if agent_type not in ['mark', 'hr']:
            return Response({
                'success': False,
                'error': 'Invalid agent type. Use "mark" or "hr"'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        health = AgentProxyService.health_check(tenant, agent_type)
        
        return Response({
            'success': health.get('healthy', False),
            'agent_type': agent_type,
            'health': health
        })


# =============================================================================
# API Key Management Views
# =============================================================================

class APIKeyListCreateView(APIView):
    """List or create API keys for a tenant."""
    
    def get(self, request, tenant_id):
        """List all API keys for a tenant."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        keys = TenantAPIKey.objects.filter(tenant=tenant)
        serializer = TenantAPIKeySerializer(keys, many=True)
        
        return Response({
            'success': True,
            'keys': serializer.data
        })
    
    def post(self, request, tenant_id):
        """Create a new API key."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = TenantAPIKeyCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the API key
        full_key, key_obj = TenantService.create_api_key(
            tenant=tenant,
            name=serializer.validated_data['name'],
            key_type=serializer.validated_data.get('key_type', 'production'),
            expires_at=serializer.validated_data.get('expires_at'),
            allowed_ips=serializer.validated_data.get('allowed_ips', [])
        )
        
        return Response({
            'success': True,
            'message': 'API key created successfully. Save this key - it will not be shown again!',
            'key': {
                'id': str(key_obj.id),
                'name': key_obj.name,
                'key_type': key_obj.key_type,
                'api_key': full_key,  # Only shown once!
                'key_prefix': key_obj.key_prefix,
                'expires_at': key_obj.expires_at
            }
        }, status=status.HTTP_201_CREATED)


class APIKeyRevokeView(APIView):
    """Revoke an API key."""
    
    def post(self, request, tenant_id, key_id):
        """Revoke an API key."""
        try:
            key = TenantAPIKey.objects.get(id=key_id, tenant_id=tenant_id)
        except TenantAPIKey.DoesNotExist:
            return Response({
                'success': False,
                'error': 'API key not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        reason = request.data.get('reason', 'Revoked by admin')
        key.revoke(reason)
        
        return Response({
            'success': True,
            'message': 'API key revoked successfully'
        })


# =============================================================================
# Agent Proxy Views (Main API for Tenants)
# =============================================================================

class AgentProxyView(APIView):
    """
    Main endpoint for tenants to interact with agents.
    Requires valid API key authentication.
    """
    authentication_classes = [TenantAPIKeyAuthentication]
    permission_classes = [HasTenantAccess]
    
    def post(self, request, agent_type):
        """
        Send a message to an agent.
        
        URL: /api/tenants/agents/{agent_type}/chat/
        Headers: X-API-Key: <your-api-key>
        """
        if agent_type not in ['mark', 'hr']:
            return Response({
                'success': False,
                'error': 'Invalid agent type. Use "mark" or "hr"'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get tenant from authentication
        tenant = request.tenant
        
        # Check if tenant has access to this agent
        has_access, reason = TenantService.check_tenant_access(tenant, agent_type)
        if not has_access:
            return Response({
                'success': False,
                'error': reason
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validate request
        serializer = AgentProxyRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid request',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check rate limit
        allowed, remaining = TenantRateLimiter.is_allowed(tenant)
        if not allowed:
            return Response({
                'success': False,
                'error': 'Rate limit exceeded. Try again later.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Proxy the request
        data = serializer.validated_data
        response = AgentProxyService.proxy_request(
            tenant=tenant,
            agent_type=agent_type,
            message=data['message'],
            session_id=data.get('session_id'),
            context=data.get('context'),
            user_id=data.get('user_id'),
            client_ip=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Add rate limit headers
        headers = {
            'X-RateLimit-Limit': str(tenant.rate_limit_per_minute),
            'X-RateLimit-Remaining': str(remaining)
        }
        
        status_code = response.get('status_code', 200)
        return Response(response, status=status_code, headers=headers)
    
    def _get_client_ip(self, request):
        """Get client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class AgentStatusView(APIView):
    """Check status and access for agents."""
    authentication_classes = [TenantAPIKeyAuthentication]
    permission_classes = [HasTenantAccess]
    
    def get(self, request):
        """Get agent access status for the authenticated tenant."""
        tenant = request.tenant
        
        # Get agent configurations
        configs = AgentConfig.objects.filter(tenant=tenant, is_enabled=True)
        agents = []
        
        for config in configs:
            agents.append({
                'agent_type': config.agent_type,
                'has_access': tenant.can_access_agent(config.agent_type),
                'endpoint_configured': bool(config.endpoint_url),
                'health_status': config.health_status,
                'last_health_check': config.last_health_check
            })
        
        # Check which agents tenant has access to
        access_status = {
            'mark': {
                'has_access': tenant.has_mark_agent_access,
                'configured': configs.filter(agent_type='mark').exists()
            },
            'hr': {
                'has_access': tenant.has_hr_agent_access,
                'configured': configs.filter(agent_type='hr').exists()
            }
        }
        
        # Rate limit info
        remaining = TenantRateLimiter.get_remaining(tenant)
        
        return Response({
            'success': True,
            'tenant': {
                'tenant_id': str(tenant.tenant_id),
                'name': tenant.name,
                'subscribed_agents': tenant.subscribed_agents,
                'status': tenant.status
            },
            'access': access_status,
            'agents': agents,
            'rate_limit': {
                'limit': tenant.rate_limit_per_minute,
                'remaining': remaining,
                'monthly_quota': tenant.monthly_quota,
                'monthly_usage': tenant.current_month_usage
            }
        })


# =============================================================================
# Subscription Management Views
# =============================================================================

class SubscriptionUpdateView(APIView):
    """Update tenant subscription."""
    
    def post(self, request, tenant_id):
        """Update tenant subscription."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = SubscriptionUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Update subscription
        tenant.subscribed_agents = serializer.validated_data['subscribed_agents']
        
        if 'subscription_end' in serializer.validated_data:
            tenant.subscription_end = serializer.validated_data['subscription_end']
        
        if 'monthly_quota' in serializer.validated_data:
            tenant.monthly_quota = serializer.validated_data['monthly_quota']
        
        tenant.save()
        
        return Response({
            'success': True,
            'message': 'Subscription updated successfully',
            'tenant': TenantSerializer(tenant).data
        })


# =============================================================================
# Request Logs Views
# =============================================================================

class RequestLogListView(APIView):
    """List request logs for a tenant."""
    
    def get(self, request, tenant_id):
        """Get request logs with optional filtering."""
        tenant = TenantService.get_tenant_by_id(tenant_id)
        if not tenant:
            return Response({
                'success': False,
                'error': 'Tenant not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        logs = AgentRequestLog.objects.filter(tenant=tenant)
        
        # Filter by agent type
        agent_type = request.query_params.get('agent_type')
        if agent_type:
            logs = logs.filter(agent_type=agent_type)
        
        # Filter by status
        status_filter = request.query_params.get('status')
        if status_filter:
            logs = logs.filter(status=status_filter)
        
        # Limit results
        limit = int(request.query_params.get('limit', 100))
        logs = logs.order_by('-created_at')[:limit]
        
        serializer = AgentRequestLogSerializer(logs, many=True)
        
        return Response({
            'success': True,
            'count': len(serializer.data),
            'logs': serializer.data
        })


# =============================================================================
# Simple Function-Based Views (Alternative)
# =============================================================================

@api_view(['POST'])
def validate_api_key(request):
    """
    Validate an API key and return tenant info.
    Useful for client-side validation.
    """
    api_key = request.data.get('api_key')
    
    if not api_key:
        return Response({
            'success': False,
            'error': 'API key is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    tenant = TenantService.get_tenant_by_api_key(api_key)
    
    if not tenant:
        return Response({
            'success': False,
            'error': 'Invalid API key'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response({
        'success': True,
        'tenant': {
            'tenant_id': str(tenant.tenant_id),
            'name': tenant.name,
            'subscribed_agents': tenant.subscribed_agents,
            'has_mark_access': tenant.has_mark_agent_access,
            'has_hr_access': tenant.has_hr_agent_access
        }
    })


@api_view(['GET'])
def tenant_stats(request, tenant_id):
    """Get usage statistics for a tenant."""
    tenant = TenantService.get_tenant_by_id(tenant_id)
    if not tenant:
        return Response({
            'success': False,
            'error': 'Tenant not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Get recent logs
    recent_logs = AgentRequestLog.objects.filter(
        tenant=tenant,
        created_at__gte=timezone.now() - timezone.timedelta(days=30)
    )
    
    # Calculate stats
    total_requests = recent_logs.count()
    success_count = recent_logs.filter(status='success').count()
    error_count = recent_logs.filter(status='error').count()
    
    # Average response time
    avg_response_time = recent_logs.filter(
        response_time_ms__isnull=False
    ).aggregate(avg=models.Avg('response_time_ms'))['avg']
    
    # Requests by agent
    mark_requests = recent_logs.filter(agent_type='mark').count()
    hr_requests = recent_logs.filter(agent_type='hr').count()
    
    return Response({
        'success': True,
        'stats': {
            'total_requests_30d': total_requests,
            'success_count': success_count,
            'error_count': error_count,
            'success_rate': (success_count / total_requests * 100) if total_requests > 0 else 0,
            'avg_response_time_ms': round(avg_response_time, 2) if avg_response_time else None,
            'by_agent': {
                'mark': mark_requests,
                'hr': hr_requests
            },
            'monthly_quota': tenant.monthly_quota,
            'current_usage': tenant.current_month_usage,
            'quota_remaining': tenant.monthly_quota - tenant.current_month_usage
        }
    })
