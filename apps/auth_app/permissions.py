"""
DRF permission classes for the SIA backend.
"""

from rest_framework.permissions import BasePermission


class IsSuperAdmin(BasePermission):
    """Only platform super-admins may access."""

    message = "Admin access required."

    def has_permission(self, request, view):
        return bool(
            request.user
            and getattr(request.user, "is_authenticated", False)
            and getattr(request.user, "role", None) == "super_admin"
            and getattr(request.user, "is_active", False)
        )


class HasAgentAccess(BasePermission):
    """
    User must have an active subscription for the requested agent type.
    The agent type is read from view kwargs (URL capture) first,
    then from the request body.
    """

    message = "You do not have an active subscription for this agent."

    def has_permission(self, request, view):
        if not request.user or not getattr(request.user, "is_authenticated", False):
            return False

        agent_type = view.kwargs.get("agent_type") or request.data.get("agent_type")
        if not agent_type:
            return False

        if agent_type == "mark":
            return request.user.can_access_mark
        if agent_type == "hr":
            return request.user.can_access_hr
        return False
