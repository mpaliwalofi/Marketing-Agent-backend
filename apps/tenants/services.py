"""
Services for tenant management and agent proxying.
"""

import requests
import json
import logging
import time
from typing import Dict, Tuple, Optional, Any
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache

from .models import Tenant, AgentConfig, TenantAPIKey, AgentRequestLog

logger = logging.getLogger(__name__)


class TenantService:
    """Service for tenant management operations."""
    
    @staticmethod
    def get_tenant_by_api_key(api_key: str) -> Optional[Tenant]:
        """
        Get tenant by API key.
        
        Args:
            api_key: The API key to look up
        
        Returns:
            Tenant or None if not found/invalid
        """
        if not api_key:
            return None
        
        # Check cache first
        cache_key = f"tenant_api_key:{api_key[:16]}"
        tenant_id = cache.get(cache_key)
        
        if tenant_id:
            try:
                return Tenant.objects.get(tenant_id=tenant_id, status__in=['active', 'trial'])
            except Tenant.DoesNotExist:
                cache.delete(cache_key)
        
        # Look up key in database
        try:
            # Find keys with matching prefix first to reduce search space
            prefix = api_key[:8] if len(api_key) >= 8 else api_key
            potential_keys = TenantAPIKey.objects.filter(
                key_prefix=prefix,
                is_active=True
            ).select_related('tenant')
            
            for key_obj in potential_keys:
                if key_obj.verify_key(api_key) and key_obj.is_valid():
                    # Cache the result
                    cache.set(cache_key, str(key_obj.tenant.tenant_id), 300)  # 5 minutes
                    key_obj.record_usage()
                    return key_obj.tenant
        except Exception as e:
            logger.error(f"Error looking up API key: {e}")
        
        return None
    
    @staticmethod
    def get_tenant_by_id(tenant_id: str) -> Optional[Tenant]:
        """
        Get tenant by tenant ID.
        
        Args:
            tenant_id: The tenant UUID
        
        Returns:
            Tenant or None if not found
        """
        try:
            return Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            return None
    
    @staticmethod
    def check_tenant_access(tenant: Tenant, agent_type: str) -> Tuple[bool, str]:
        """
        Check if a tenant has access to a specific agent.
        
        Args:
            tenant: The tenant to check
            agent_type: 'mark' or 'hr'
        
        Returns:
            Tuple of (has_access, reason)
        """
        if not tenant:
            return False, "Tenant not found"
        
        if not tenant.is_active:
            return False, f"Tenant subscription is {tenant.status}"
        
        if not tenant.can_access_agent(agent_type):
            return False, f"Tenant does not have access to {agent_type} agent"
        
        if not tenant.is_within_quota():
            return False, "Monthly quota exceeded"
        
        return True, "Access granted"
    
    @staticmethod
    def create_api_key(tenant: Tenant, name: str, key_type: str = 'production',
                       expires_at=None, allowed_ips=None) -> Tuple[str, TenantAPIKey]:
        """
        Create a new API key for a tenant.
        
        Args:
            tenant: The tenant to create key for
            name: Descriptive name for the key
            key_type: Type of key (production, sandbox, webhook)
            expires_at: Optional expiration datetime
            allowed_ips: Optional list of allowed IP addresses
        
        Returns:
            Tuple of (full_key, key_object)
        """
        full_key, key_hash, key_prefix = TenantAPIKey.generate_key()
        
        key_obj = TenantAPIKey.objects.create(
            tenant=tenant,
            name=name,
            key_type=key_type,
            key_hash=key_hash,
            key_prefix=key_prefix,
            expires_at=expires_at,
            allowed_ips=allowed_ips or []
        )
        
        return full_key, key_obj
    
    @staticmethod
    def rotate_api_key(key_obj: TenantAPIKey, reason: str = None) -> str:
        """
        Rotate an API key (revoke old and create new).
        
        Args:
            key_obj: The key to rotate
            reason: Reason for rotation
        
        Returns:
            The new full API key
        """
        # Revoke old key
        key_obj.revoke(reason or "Key rotation")
        
        # Create new key with same settings
        full_key, _ = TenantService.create_api_key(
            tenant=key_obj.tenant,
            name=key_obj.name,
            key_type=key_obj.key_type,
            expires_at=key_obj.expires_at,
            allowed_ips=key_obj.allowed_ips
        )
        
        return full_key


class AgentProxyService:
    """
    Service for proxying requests to external agent backends.
    Handles Mark's Agent (n8n) and HR Agent (AWS).
    """
    
    @staticmethod
    def get_agent_config(tenant: Tenant, agent_type: str) -> Optional[AgentConfig]:
        """
        Get agent configuration for a tenant.
        
        Args:
            tenant: The tenant
            agent_type: 'mark' or 'hr'
        
        Returns:
            AgentConfig or None
        """
        try:
            return AgentConfig.objects.get(
                tenant=tenant,
                agent_type=agent_type,
                is_enabled=True
            )
        except AgentConfig.DoesNotExist:
            return None
    
    @staticmethod
    def proxy_request(
        tenant: Tenant,
        agent_type: str,
        message: str,
        session_id: str = None,
        context: Dict = None,
        user_id: str = None,
        client_ip: str = None,
        user_agent: str = None
    ) -> Dict:
        """
        Proxy a request to the external agent backend.
        
        Args:
            tenant: The tenant making the request
            agent_type: 'mark' or 'hr'
            message: The message to send
            session_id: Optional session ID for continuity
            context: Optional additional context
            user_id: Optional user ID within the tenant
            client_ip: Client IP address for logging
            user_agent: Client user agent for logging
        
        Returns:
            Dict with response data
        """
        start_time = time.time()
        request_id = None
        
        # Check tenant access
        has_access, reason = TenantService.check_tenant_access(tenant, agent_type)
        if not has_access:
            logger.warning(f"Access denied for tenant {tenant.tenant_id}: {reason}")
            return {
                'success': False,
                'error': reason,
                'status_code': 403
            }
        
        # Get agent configuration
        agent_config = AgentProxyService.get_agent_config(tenant, agent_type)
        if not agent_config:
            logger.error(f"Agent config not found for tenant {tenant.tenant_id}, agent {agent_type}")
            return {
                'success': False,
                'error': f"Agent configuration not found for {agent_type}",
                'status_code': 404
            }
        
        # Prepare request payload
        payload = {
            'message': message,
            'tenant_id': str(tenant.tenant_id),
            'tenant_name': tenant.name,
        }
        
        if session_id:
            payload['session_id'] = session_id
        if context:
            payload['context'] = context
        if user_id:
            payload['user_id'] = user_id
        
        # Get authentication headers
        headers = agent_config.get_auth_headers()
        headers.update({
            'Content-Type': 'application/json',
            'X-Tenant-ID': str(tenant.tenant_id),
            'X-Request-ID': str(request_id) if request_id else '',
        })
        
        response_data = None
        status = 'error'
        status_code = None
        error_message = None
        response_body = None
        
        try:
            # Make request to external agent
            response = requests.post(
                agent_config.endpoint_url,
                headers=headers,
                json=payload,
                timeout=agent_config.timeout_seconds
            )
            
            status_code = response.status_code
            response_time_ms = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    status = 'success'
                    response_body = response_data
                except json.JSONDecodeError:
                    response_data = {'response': response.text}
                    response_body = {'response': response.text[:1000]}
                    status = 'success'
            else:
                error_message = f"Agent returned status {response.status_code}: {response.text[:500]}"
                logger.error(error_message)
                
                # Determine status category
                if response.status_code == 429:
                    status = 'rate_limited'
                elif response.status_code in [401, 403]:
                    status = 'unauthorized'
                else:
                    status = 'error'
                
                response_data = {
                    'success': False,
                    'error': f"Agent error: {response.status_code}",
                    'status_code': response.status_code
                }
        
        except requests.exceptions.Timeout:
            response_time_ms = int((time.time() - start_time) * 1000)
            status = 'timeout'
            error_message = "Request to agent timed out"
            logger.error(error_message)
            response_data = {
                'success': False,
                'error': 'Agent request timed out',
                'status_code': 504
            }
        
        except requests.exceptions.RequestException as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            status = 'error'
            error_message = f"Request to agent failed: {str(e)}"
            logger.error(error_message)
            response_data = {
                'success': False,
                'error': 'Failed to connect to agent',
                'status_code': 502
            }
        
        # Log the request
        try:
            AgentRequestLog.objects.create(
                tenant=tenant,
                agent_type=agent_type,
                request_method='POST',
                request_path=agent_config.endpoint_url,
                request_headers={k: v for k, v in headers.items() if k.lower() not in ['authorization', 'x-api-secret']},
                request_body=payload,
                status=status,
                status_code=status_code,
                response_body=response_body if isinstance(response_body, dict) else {'response': str(response_body)[:1000]} if response_body else None,
                error_message=error_message,
                response_time_ms=response_time_ms,
                client_ip=client_ip,
                user_agent=user_agent[:500] if user_agent else None
            )
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
        
        return response_data
    
    @staticmethod
    def health_check(tenant: Tenant, agent_type: str) -> Dict:
        """
        Perform a health check on an agent configuration.
        
        Args:
            tenant: The tenant
            agent_type: 'mark' or 'hr'
        
        Returns:
            Dict with health status
        """
        agent_config = AgentProxyService.get_agent_config(tenant, agent_type)
        if not agent_config:
            return {
                'healthy': False,
                'error': 'Agent configuration not found'
            }
        
        try:
            headers = agent_config.get_auth_headers()
            
            # Try a simple health check - different agents may have different endpoints
            health_url = agent_config.endpoint_url.replace('/chat', '/health').replace('/webhook', '/health')
            
            response = requests.get(
                health_url,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                agent_config.health_status = 'healthy'
                agent_config.last_health_check = timezone.now()
                agent_config.save(update_fields=['health_status', 'last_health_check'])
                return {
                    'healthy': True,
                    'response_time_ms': int(response.elapsed.total_seconds() * 1000)
                }
            else:
                agent_config.health_status = 'unhealthy'
                agent_config.last_health_check = timezone.now()
                agent_config.save(update_fields=['health_status', 'last_health_check'])
                return {
                    'healthy': False,
                    'error': f'Health check returned {response.status_code}'
                }
        
        except Exception as e:
            agent_config.health_status = 'unhealthy'
            agent_config.last_health_check = timezone.now()
            agent_config.save(update_fields=['health_status', 'last_health_check'])
            return {
                'healthy': False,
                'error': str(e)
            }


class TenantRateLimiter:
    """
    Rate limiting service for tenants.
    Uses Redis/cache for distributed rate limiting.
    """
    
    @staticmethod
    def is_allowed(tenant: Tenant, key: str = None) -> Tuple[bool, int]:
        """
        Check if a request is allowed under rate limits.
        
        Args:
            tenant: The tenant
            key: Optional specific key to rate limit
        
        Returns:
            Tuple of (allowed, remaining_requests)
        """
        cache_key = f"rate_limit:{tenant.tenant_id}:{key or 'default'}"
        
        # Get current count
        current = cache.get(cache_key, 0)
        
        # Check if over limit
        if current >= tenant.rate_limit_per_minute:
            return False, 0
        
        # Increment counter
        try:
            # Set with 1-minute expiry if not exists
            cache.set(cache_key, current + 1, 60)
        except Exception:
            pass
        
        remaining = tenant.rate_limit_per_minute - current - 1
        return True, remaining
    
    @staticmethod
    def get_remaining(tenant: Tenant, key: str = None) -> int:
        """Get remaining requests for a tenant."""
        cache_key = f"rate_limit:{tenant.tenant_id}:{key or 'default'}"
        current = cache.get(cache_key, 0)
        return max(0, tenant.rate_limit_per_minute - current)
