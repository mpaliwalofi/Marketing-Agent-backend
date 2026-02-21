"""
Services for tenant management and agent proxying.
"""

import requests
import logging
import time
from typing import Dict, Optional, Tuple, Any

from django.core.cache import cache
from django.utils import timezone

from .models import Tenant, AgentConfig, TenantAPIKey, AgentRequestLog

logger = logging.getLogger(__name__)


class TenantService:

    @staticmethod
    def get_tenant_by_api_key(api_key: str) -> Optional[Tuple[Tenant, Any]]:
        """
        Look up a Tenant by API key.
        Returns (Tenant, user_profile_or_None) or None if the key is invalid.

        user_profile is the first active member of the tenant (used as request.user
        so that DRF permission checks work). If the tenant has no members yet,
        returns None for the user — views should handle this gracefully.
        """
        if not api_key:
            return None

        # Cache look-up to avoid hashing on every request
        cache_key = f"api_key_tenant:{api_key[:16]}"
        tenant_id = cache.get(cache_key)

        if tenant_id:
            try:
                tenant = Tenant.objects.get(
                    tenant_id=tenant_id,
                    subscription_status__in=("active", "trial"),
                    is_active=True,
                )
                user_profile = (
                    tenant.members.filter(is_active=True).first()
                )
                return tenant, user_profile
            except Tenant.DoesNotExist:
                cache.delete(cache_key)

        # Search by key prefix to narrow the hash comparison
        prefix = api_key[:10] if len(api_key) >= 10 else api_key
        candidates = TenantAPIKey.objects.filter(
            key_prefix=prefix, is_active=True
        ).select_related("tenant")

        for key_obj in candidates:
            if key_obj.verify_key(api_key) and key_obj.is_valid():
                tenant = key_obj.tenant
                if not (tenant.is_active and tenant.is_subscription_active):
                    return None

                cache.set(cache_key, str(tenant.tenant_id), 300)
                key_obj.record_usage()

                user_profile = tenant.members.filter(is_active=True).first()
                return tenant, user_profile

        return None


class AgentProxyService:
    """Forwards requests to external agent backends."""

    @staticmethod
    def forward_request(
        config: AgentConfig,
        payload: Dict,
        client_ip: str = None,
        user=None,
    ) -> Dict:
        """
        Send a chat payload to the external agent endpoint and return a
        standardised result dict.
        """
        start = time.time()
        tenant = config.tenant
        log_kwargs = {
            "tenant": tenant,
            "user": user,
            "agent_type": config.agent_type,
            "client_ip": client_ip,
        }

        if not tenant.is_within_quota():
            AgentRequestLog.objects.create(
                **log_kwargs,
                status="rate_limited",
                status_code=429,
                response_time_ms=0,
                error_message="Monthly quota exceeded",
            )
            return {
                "success": False,
                "error": "Monthly quota exceeded",
                "status_code": 429,
            }

        headers = {"Content-Type": "application/json"}
        headers.update(config.get_auth_headers())

        last_error = None
        for attempt in range(1, config.max_retries + 1):
            try:
                response = requests.post(
                    config.endpoint_url,
                    json=payload,
                    headers=headers,
                    timeout=config.timeout_seconds,
                )
                elapsed_ms = int((time.time() - start) * 1000)

                if response.status_code < 500:
                    # Treat anything below 500 as a definitive answer
                    status = "success" if response.status_code < 400 else "error"
                    AgentRequestLog.objects.create(
                        **log_kwargs,
                        status=status,
                        status_code=response.status_code,
                        response_time_ms=elapsed_ms,
                    )
                    return {
                        "success": status == "success",
                        "data": response.json() if response.text else {},
                        "status_code": response.status_code,
                    }
                last_error = f"HTTP {response.status_code}"

            except requests.exceptions.Timeout:
                last_error = "Request timed out"
                if attempt == config.max_retries:
                    elapsed_ms = int((time.time() - start) * 1000)
                    AgentRequestLog.objects.create(
                        **log_kwargs,
                        status="timeout",
                        status_code=None,
                        response_time_ms=elapsed_ms,
                        error_message=last_error,
                    )
                    return {"success": False, "error": last_error, "status_code": 504}

            except requests.exceptions.RequestException as exc:
                last_error = str(exc)
                break

        elapsed_ms = int((time.time() - start) * 1000)
        AgentRequestLog.objects.create(
            **log_kwargs,
            status="error",
            status_code=None,
            response_time_ms=elapsed_ms,
            error_message=last_error,
        )
        return {"success": False, "error": last_error, "status_code": 502}
