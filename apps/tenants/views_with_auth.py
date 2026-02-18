"""
Updated agent proxy views with Supabase authentication.
This extends the existing views to support both API Key and Supabase JWT auth.
"""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
import logging

from .models import AgentConfig
from .serializers import AgentProxyRequestSerializer
from .services import AgentProxyService, TenantRateLimiter
from apps.auth_app.permissions import IsSupabaseUser, CanAccessAgent
from apps.auth_app.authentication import APIKeyOrSupabaseAuth

logger = logging.getLogger(__name__)


class AgentProxyWithAuthView(APIView):
    """
    Agent proxy endpoint that supports both:
    - Supabase JWT authentication (for web users)
    - API Key authentication (for service integrations)
    
    Priority: Supabase JWT > API Key
    """
    
    authentication_classes = [APIKeyOrSupabaseAuth]
    permission_classes = [IsSupabaseUser, CanAccessAgent]
    
    def post(self, request, agent_type):
        """
        Send a message to an agent.
        
        Headers:
            Authorization: Bearer <supabase-jwt-token>
            OR
            X-API-Key: <tenant-api-key>
        
        Body:
            {
                "message": "Hello!",
                "session_id": "optional-session-id",
                "context": {},
                "user_id": "optional-user-id"
            }
        """
        if agent_type not in ['mark', 'hr']:
            return Response({
                'success': False,
                'error': 'Invalid agent type. Use "mark" or "hr"'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get tenant from request (set by authentication)
        tenant = getattr(request, 'tenant', None)
        supabase_user = getattr(request, 'supabase_user', None)
        
        if not tenant:
            return Response({
                'success': False,
                'error': 'No tenant associated with this account'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Check tenant has access to this agent
        if not tenant.can_access_agent(agent_type):
            return Response({
                'success': False,
                'error': f'Your subscription does not include access to {agent_type} agent'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Check user has access to this agent
        if supabase_user and not supabase_user.has_agent_access(agent_type):
            return Response({
                'success': False,
                'error': 'You do not have permission to access this agent'
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
        
        # Get user ID for context
        user_id = serializer.validated_data.get('user_id')
        if supabase_user and not user_id:
            user_id = str(supabase_user.id)
        
        # Add user context
        context = serializer.validated_data.get('context', {})
        if supabase_user:
            context['_auth'] = {
                'user_id': str(supabase_user.id),
                'email': supabase_user.email,
                'role': supabase_user.role,
                'tenant_id': str(tenant.tenant_id)
            }
        
        # Proxy the request
        response = AgentProxyService.proxy_request(
            tenant=tenant,
            agent_type=agent_type,
            message=serializer.validated_data['message'],
            session_id=serializer.validated_data.get('session_id'),
            context=context,
            user_id=user_id,
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


class AgentStatusWithAuthView(APIView):
    """
    Check agent status with authentication.
    """
    
    authentication_classes = [APIKeyOrSupabaseAuth]
    permission_classes = [IsSupabaseUser]
    
    def get(self, request):
        """Get agent access status for the authenticated user."""
        tenant = getattr(request, 'tenant', None)
        supabase_user = getattr(request, 'supabase_user', None)
        
        if not tenant:
            return Response({
                'success': False,
                'error': 'No tenant associated with this account'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get agent configurations
        configs = AgentConfig.objects.filter(tenant=tenant, is_enabled=True)
        agents = []
        
        for config in configs:
            # Check if user has access to this agent
            user_has_access = supabase_user.has_agent_access(config.agent_type) if supabase_user else True
            
            agents.append({
                'agent_type': config.agent_type,
                'has_access': tenant.can_access_agent(config.agent_type) and user_has_access,
                'endpoint_configured': bool(config.endpoint_url),
                'health_status': config.health_status,
                'last_health_check': config.last_health_check
            })
        
        # Check which agents tenant has access to
        access_status = {
            'mark': {
                'has_access': tenant.has_mark_agent_access,
                'user_has_access': supabase_user.has_agent_access('mark') if supabase_user else True,
                'configured': configs.filter(agent_type='mark').exists()
            },
            'hr': {
                'has_access': tenant.has_hr_agent_access,
                'user_has_access': supabase_user.has_agent_access('hr') if supabase_user else True,
                'configured': configs.filter(agent_type='hr').exists()
            }
        }
        
        # Rate limit info
        remaining = TenantRateLimiter.get_remaining(tenant)
        
        # User info
        user_info = None
        if supabase_user:
            user_info = {
                'id': str(supabase_user.id),
                'email': supabase_user.email,
                'role': supabase_user.role
            }
        
        return Response({
            'success': True,
            'user': user_info,
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
