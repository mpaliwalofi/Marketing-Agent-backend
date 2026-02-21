"""
Agent proxy views.

These endpoints allow tenants (via API key) or logged-in users (via JWT)
to send messages to external agent backends.
"""

import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AgentConfig
from .services import AgentProxyService
from apps.auth_app.permissions import HasAgentAccess

logger = logging.getLogger(__name__)


def _get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR", "")


class AgentProxyView(APIView):
    """
    POST /api/agents/<agent_type>/chat/

    Accepts: JWT (logged-in user) or X-API-Key (tenant widget).
    Returns: forwarded response from the external agent backend.

    Body: any JSON payload — passed through to the agent as-is.
    """

    permission_classes = [IsAuthenticated, HasAgentAccess]

    def post(self, request, agent_type):
        # Determine which tenant owns this request
        user = request.user  # UserProfile
        tenant = getattr(user, "tenant", None) or getattr(request, "tenant", None)

        if not tenant:
            return Response(
                {"success": False, "error": "No tenant subscription found."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            config = AgentConfig.objects.get(
                tenant=tenant, agent_type=agent_type, is_enabled=True
            )
        except AgentConfig.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "error": f"Agent '{agent_type}' is not configured for your account.",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        result = AgentProxyService.forward_request(
            config=config,
            payload=request.data,
            client_ip=_get_client_ip(request),
            user=user if hasattr(user, "id") else None,
        )

        http_status = status.HTTP_200_OK if result["success"] else result.get("status_code", 502)
        return Response(result, status=http_status)


class AgentStatusView(APIView):
    """
    GET /api/agents/status/

    Returns the current user's agent access information.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        tenant = getattr(user, "tenant", None) or getattr(request, "tenant", None)

        return Response({
            "success": True,
            "data": {
                "can_access_mark": user.can_access_mark,
                "can_access_hr": user.can_access_hr,
                "accessible_agents": user.get_accessible_agents(),
                "tenant": {
                    "id": str(tenant.tenant_id),
                    "name": tenant.name,
                    "subscription_type": tenant.subscription_type,
                    "subscription_status": tenant.subscription_status,
                } if tenant else None,
            },
        })
