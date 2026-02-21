"""
Admin portal views — all endpoints require IsSuperAdmin permission.

Provides user management, tenant management, subscription assignment,
API key management, and dashboard stats/logs.
"""

import logging
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from django.utils import timezone

from .models import UserProfile
from .permissions import IsSuperAdmin
from .serializers import (
    AdminUserListSerializer, AdminUserDetailSerializer, AssignTenantSerializer,
)
from apps.tenants.models import Tenant, AgentConfig, TenantAPIKey, AgentRequestLog
from apps.tenants.serializers import (
    TenantSerializer, TenantCreateSerializer, TenantUpdateSerializer,
    AgentConfigSerializer, TenantAPIKeySerializer, TenantAPIKeyCreateSerializer,
    AgentRequestLogSerializer,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# User management                                                       #
# ------------------------------------------------------------------ #

class AdminUserListView(APIView):
    """GET /api/admin/users/ — list all registered users."""

    permission_classes = [IsSuperAdmin]

    def get(self, request):
        users = UserProfile.objects.select_related("tenant").order_by("-created_at")

        # Optional filters
        if role := request.query_params.get("role"):
            users = users.filter(role=role)
        if sub_status := request.query_params.get("subscription_status"):
            users = users.filter(tenant__subscription_status=sub_status)
        if search := request.query_params.get("search"):
            users = users.filter(email__icontains=search)

        serializer = AdminUserListSerializer(users, many=True)
        return Response({"success": True, "count": users.count(), "users": serializer.data})


class AdminUserDetailView(APIView):
    """GET /api/admin/users/<uuid>/ — single user detail."""

    permission_classes = [IsSuperAdmin]

    def get(self, request, user_id):
        try:
            user = UserProfile.objects.select_related("tenant").get(id=user_id)
        except UserProfile.DoesNotExist:
            return Response(
                {"success": False, "error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"success": True, "data": AdminUserDetailSerializer(user).data})


class AdminUserStatusView(APIView):
    """PATCH /api/admin/users/<uuid>/status/ — toggle is_active."""

    permission_classes = [IsSuperAdmin]

    def patch(self, request, user_id):
        try:
            user = UserProfile.objects.get(id=user_id)
        except UserProfile.DoesNotExist:
            return Response(
                {"success": False, "error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if user.role == "super_admin":
            return Response(
                {"success": False, "error": "Cannot deactivate a super admin."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_active = not user.is_active
        user.save(update_fields=["is_active"])
        return Response({
            "success": True,
            "message": f"User {'activated' if user.is_active else 'deactivated'}.",
            "is_active": user.is_active,
        })


class AdminUserAssignTenantView(APIView):
    """PATCH /api/admin/users/<uuid>/tenant/ — assign or remove tenant."""

    permission_classes = [IsSuperAdmin]

    def patch(self, request, user_id):
        try:
            user = UserProfile.objects.get(id=user_id)
        except UserProfile.DoesNotExist:
            return Response(
                {"success": False, "error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = AssignTenantSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        tenant_id = serializer.validated_data.get("tenant_id")

        if tenant_id:
            try:
                tenant = Tenant.objects.get(tenant_id=tenant_id)
            except Tenant.DoesNotExist:
                return Response(
                    {"success": False, "error": "Tenant not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            user.tenant = tenant
        else:
            user.tenant = None  # Remove from tenant

        user.save(update_fields=["tenant"])
        return Response({
            "success": True,
            "message": f"User assigned to {'tenant ' + str(tenant_id) if tenant_id else 'no tenant'}.",
            "data": AdminUserDetailSerializer(user).data,
        })


# ------------------------------------------------------------------ #
# Tenant management                                                     #
# ------------------------------------------------------------------ #

class AdminTenantListView(APIView):
    """GET/POST /api/admin/tenants/"""

    permission_classes = [IsSuperAdmin]

    def get(self, request):
        tenants = Tenant.objects.all().order_by("-created_at")
        if sub_status := request.query_params.get("status"):
            tenants = tenants.filter(subscription_status=sub_status)
        serializer = TenantSerializer(tenants, many=True)
        return Response({"success": True, "count": tenants.count(), "tenants": serializer.data})

    def post(self, request):
        serializer = TenantCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Auto-set subscription_start when status is active/trial
        tenant = serializer.save()
        if tenant.subscription_status in ("active", "trial") and not tenant.subscription_start:
            tenant.subscription_start = timezone.now()
            tenant.save(update_fields=["subscription_start"])

        return Response(
            {"success": True, "message": "Tenant created.", "data": TenantSerializer(tenant).data},
            status=status.HTTP_201_CREATED,
        )


class AdminTenantDetailView(APIView):
    """GET/PATCH/DELETE /api/admin/tenants/<uuid>/"""

    permission_classes = [IsSuperAdmin]

    def _get_tenant(self, tenant_id):
        try:
            return Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            return None

    def get(self, request, tenant_id):
        tenant = self._get_tenant(tenant_id)
        if not tenant:
            return Response(
                {"success": False, "error": "Tenant not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"success": True, "data": TenantSerializer(tenant).data})

    def patch(self, request, tenant_id):
        tenant = self._get_tenant(tenant_id)
        if not tenant:
            return Response(
                {"success": False, "error": "Tenant not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = TenantUpdateSerializer(tenant, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
        tenant = serializer.save()
        return Response({
            "success": True,
            "message": "Tenant updated.",
            "data": TenantSerializer(tenant).data,
        })

    def delete(self, request, tenant_id):
        tenant = self._get_tenant(tenant_id)
        if not tenant:
            return Response(
                {"success": False, "error": "Tenant not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Unlink members before deleting
        tenant.members.all().update(tenant=None)
        tenant.delete()
        return Response({"success": True, "message": "Tenant deleted."})


# ------------------------------------------------------------------ #
# Agent config (per tenant)                                            #
# ------------------------------------------------------------------ #

class AdminAgentConfigView(APIView):
    """
    GET  /api/admin/tenants/<uuid>/agent-configs/
    PUT  /api/admin/tenants/<uuid>/agent-configs/<type>/
    """

    permission_classes = [IsSuperAdmin]

    def get(self, request, tenant_id):
        try:
            tenant = Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            return Response({"success": False, "error": "Tenant not found."}, status=404)

        configs = AgentConfig.objects.filter(tenant=tenant)
        return Response({"success": True, "configs": AgentConfigSerializer(configs, many=True).data})

    def put(self, request, tenant_id, agent_type):
        try:
            tenant = Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            return Response({"success": False, "error": "Tenant not found."}, status=404)

        config, _ = AgentConfig.objects.get_or_create(
            tenant=tenant, agent_type=agent_type
        )
        serializer = AgentConfigSerializer(config, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response({"success": False, "errors": serializer.errors}, status=400)
        serializer.save()
        return Response({"success": True, "config": serializer.data})


# ------------------------------------------------------------------ #
# API key management (per tenant)                                      #
# ------------------------------------------------------------------ #

class AdminTenantAPIKeyView(APIView):
    """
    GET  /api/admin/tenants/<uuid>/keys/  — list keys
    POST /api/admin/tenants/<uuid>/keys/  — create key (returns plaintext once)
    """

    permission_classes = [IsSuperAdmin]

    def get(self, request, tenant_id):
        try:
            tenant = Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            return Response({"success": False, "error": "Tenant not found."}, status=404)

        keys = TenantAPIKey.objects.filter(tenant=tenant)
        return Response({"success": True, "keys": TenantAPIKeySerializer(keys, many=True).data})

    def post(self, request, tenant_id):
        try:
            tenant = Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            return Response({"success": False, "error": "Tenant not found."}, status=404)

        serializer = TenantAPIKeyCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"success": False, "errors": serializer.errors}, status=400)

        full_key, key_hash, prefix = TenantAPIKey.generate_key()
        api_key = TenantAPIKey.objects.create(
            tenant=tenant,
            name=serializer.validated_data["name"],
            key_hash=key_hash,
            key_prefix=prefix,
            expires_at=serializer.validated_data.get("expires_at"),
        )

        return Response({
            "success": True,
            "message": "API key created. Copy the key now — it will not be shown again.",
            "key": full_key,
            "key_id": str(api_key.id),
            "prefix": prefix,
        }, status=status.HTTP_201_CREATED)


class AdminTenantAPIKeyRevokeView(APIView):
    """POST /api/admin/tenants/<uuid>/keys/<key_id>/revoke/"""

    permission_classes = [IsSuperAdmin]

    def post(self, request, tenant_id, key_id):
        try:
            key = TenantAPIKey.objects.get(id=key_id, tenant__tenant_id=tenant_id)
        except TenantAPIKey.DoesNotExist:
            return Response({"success": False, "error": "API key not found."}, status=404)

        key.revoke()
        return Response({"success": True, "message": "API key revoked."})


# ------------------------------------------------------------------ #
# Dashboard stats & logs                                               #
# ------------------------------------------------------------------ #

class AdminStatsView(APIView):
    """GET /api/admin/stats/"""

    permission_classes = [IsSuperAdmin]

    def get(self, request):
        total_users = UserProfile.objects.filter(role="user").count()
        active_subs = UserProfile.objects.filter(
            tenant__subscription_status__in=("active", "trial"),
            role="user",
            is_active=True,
        ).count()

        stats = {
            "total_users": total_users,
            "active_subscriptions": active_subs,
            "subscriptions_by_type": {
                "mark": Tenant.objects.filter(
                    subscription_type="mark", subscription_status="active"
                ).count(),
                "hr": Tenant.objects.filter(
                    subscription_type="hr", subscription_status="active"
                ).count(),
                "both": Tenant.objects.filter(
                    subscription_type="both", subscription_status="active"
                ).count(),
            },
            "total_tenants": Tenant.objects.count(),
            "total_api_requests": AgentRequestLog.objects.count(),
            "requests_today": AgentRequestLog.objects.filter(
                created_at__date=timezone.now().date()
            ).count(),
        }
        return Response({"success": True, "data": stats})


class AdminLogsView(APIView):
    """GET /api/admin/logs/ — last 100 agent request logs."""

    permission_classes = [IsSuperAdmin]

    def get(self, request):
        logs = (
            AgentRequestLog.objects
            .select_related("user", "tenant")
            .order_by("-created_at")[:100]
        )
        serializer = AgentRequestLogSerializer(logs, many=True)
        return Response({"success": True, "count": len(serializer.data), "logs": serializer.data})
