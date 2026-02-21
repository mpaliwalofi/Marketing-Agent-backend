"""
DRF authentication class for Tenant API keys.

API keys are passed via the X-API-Key header (preferred) or as a Bearer token.
On success, sets request.user = UserProfile of a member of the tenant,
or None for a keyless widget call, and request.auth = Tenant.
"""

import logging
from rest_framework import authentication, exceptions

from .services import TenantService

logger = logging.getLogger(__name__)


class TenantAPIKeyAuthentication(authentication.BaseAuthentication):
    """
    Authenticates requests using a Tenant API key.

    Header (preferred):   X-API-Key: sia_xxx...
    Alternative:          Authorization: Bearer sia_xxx...

    On success:
      request.user   = UserProfile (first active member of the tenant, or None)
      request.auth   = Tenant instance
      request.tenant = Tenant instance  (set explicitly for convenience)
    """

    def authenticate(self, request):
        # Prefer the dedicated header
        api_key = request.META.get("HTTP_X_API_KEY")

        # Fall back to Authorization: Bearer only when it is NOT a JWT
        if not api_key:
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header.startswith("Bearer "):
                candidate = auth_header[7:].strip()
                # JWTs have exactly two dots; API keys do not
                if candidate.count(".") != 2:
                    api_key = candidate

        if not api_key:
            return None

        result = TenantService.get_tenant_by_api_key(api_key)
        if not result:
            raise exceptions.AuthenticationFailed("Invalid or inactive API key")

        tenant, user_profile = result

        # Attach tenant for easy access in views
        request.tenant = tenant

        return (user_profile, tenant)

    def authenticate_header(self, request):
        return "X-API-Key"
