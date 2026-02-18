"""
Permission classes for tenant access control.
"""

from rest_framework import permissions
from .services import TenantService


class HasTenantAccess(permissions.BasePermission):
    """
    Permission that checks if the authenticated tenant has active subscription.
    """
    
    message = 'Tenant does not have active subscription'
    
    def has_permission(self, request, view):
        # Check if tenant is attached to request
        tenant = getattr(request, 'tenant', None)
        
        if not tenant:
            return False
        
        # Check if tenant is active
        if not tenant.is_active:
            self.message = f'Tenant subscription is {tenant.status}'
            return False
        
        return True


class HasAgentAccess(permissions.BasePermission):
    """
    Permission that checks if tenant has access to a specific agent.
    The agent_type should be in view.kwargs.
    """
    
    message = 'Tenant does not have access to this agent'
    
    def has_permission(self, request, view):
        tenant = getattr(request, 'tenant', None)
        
        if not tenant:
            return False
        
        # Get agent type from URL kwargs
        agent_type = view.kwargs.get('agent_type')
        
        if not agent_type:
            return False
        
        has_access, reason = TenantService.check_tenant_access(tenant, agent_type)
        
        if not has_access:
            self.message = reason
            return False
        
        return True


class IsTenantAdmin(permissions.BasePermission):
    """
    Permission for tenant admin operations.
    In a real implementation, this would check if the user is an admin of the tenant.
    """
    
    message = 'Admin access required'
    
    def has_permission(self, request, view):
        # For now, allow all authenticated requests
        # In production, check user roles
        return True


class HasAPIKey(permissions.BasePermission):
    """
    Simple permission that just checks for valid API key authentication.
    """
    
    message = 'Valid API key required'
    
    def has_permission(self, request, view):
        return hasattr(request, 'tenant') and request.tenant is not None
