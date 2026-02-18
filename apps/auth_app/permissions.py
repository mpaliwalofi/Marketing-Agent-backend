"""
Permission classes for Supabase-authenticated users.
"""

from rest_framework import permissions
from .services import UserPermissionService


class IsSupabaseUser(permissions.BasePermission):
    """
    Permission that checks if user is authenticated via Supabase.
    """
    
    message = 'Authentication required'
    
    def has_permission(self, request, view):
        return hasattr(request, 'supabase_user') and request.supabase_user is not None


class HasTenantAccess(permissions.BasePermission):
    """
    Permission that checks if user has an active tenant.
    """
    
    message = 'Active tenant subscription required'
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        supabase_user = request.supabase_user
        if not supabase_user or not supabase_user.tenant:
            return False
        
        return supabase_user.tenant.is_active


class CanAccessMarkAgent(permissions.BasePermission):
    """
    Permission that checks if user can access Mark's Agent.
    """
    
    message = 'Access to Mark\'s Agent not allowed'
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        return request.supabase_user.has_agent_access('mark')


class CanAccessHRAgent(permissions.BasePermission):
    """
    Permission that checks if user can access HR Agent.
    """
    
    message = 'Access to HR Agent not allowed'
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        return request.supabase_user.has_agent_access('hr')


class CanAccessAgent(permissions.BasePermission):
    """
    Permission that checks access to a specific agent type.
    Agent type should be in view.kwargs as 'agent_type'.
    """
    
    message = 'Access to this agent not allowed'
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        agent_type = view.kwargs.get('agent_type')
        if not agent_type:
            return False
        
        return request.supabase_user.has_agent_access(agent_type)


class IsTenantAdmin(permissions.BasePermission):
    """
    Permission that checks if user is a tenant admin.
    """
    
    message = 'Admin access required'
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        return UserPermissionService.is_tenant_admin(request.supabase_user)


class IsTenantManager(permissions.BasePermission):
    """
    Permission that checks if user is a tenant admin or manager.
    """
    
    message = 'Manager access required'
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        return UserPermissionService.can_manage_users(request.supabase_user)


class HasRole(permissions.BasePermission):
    """
    Permission that checks if user has one of the allowed roles.
    
    Usage:
        permission_classes = [HasRole]
        allowed_roles = ['admin', 'manager']
    """
    
    message = 'Insufficient permissions'
    allowed_roles = []
    
    def has_permission(self, request, view):
        if not hasattr(request, 'supabase_user'):
            return False
        
        # Get allowed roles from view or use default
        allowed = getattr(view, 'allowed_roles', self.allowed_roles)
        
        return request.supabase_user.role in allowed
