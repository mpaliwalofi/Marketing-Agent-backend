"""
DRF authentication class for Supabase JWT tokens.

Returns UserProfile as request.user (UserProfile.is_authenticated = True).
Django's auth.User is never involved in API authentication.
"""

import logging
from rest_framework import authentication, exceptions

from .supabase_client import supabase_auth
from .models import UserProfile

logger = logging.getLogger(__name__)


class SupabaseJWTAuthentication(authentication.BaseAuthentication):
    """
    Authenticates Bearer JWT tokens issued by Supabase.

    On success sets:
      request.user        = UserProfile instance
      request.auth        = None  (token payload not needed downstream)
    """

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode("utf-8")

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:].strip()
        if not token:
            return None

        # JWTs always have exactly two dots (header.payload.signature).
        # Supabase/tenant API keys do not — skip them here.
        if token.count(".") != 2:
            return None

        is_valid, result = supabase_auth.verify_jwt(token)
        if not is_valid:
            raise exceptions.AuthenticationFailed(result.get("error", "Invalid token"))

        # 'sub' comes from a locally decoded JWT payload; 'id' from the Supabase API response.
        supabase_uid = result.get("sub") or result.get("id")
        email = result.get("email")

        if not supabase_uid:
            raise exceptions.AuthenticationFailed("Invalid token: missing user ID")

        try:
            profile = self._get_or_create_profile(supabase_uid, email, result)
        except Exception as exc:
            logger.error("Failed to get/create UserProfile: %s", exc)
            raise exceptions.AuthenticationFailed("Authentication failed")

        if not profile.is_active:
            raise exceptions.AuthenticationFailed("User account is deactivated")

        # Sync email_confirmed flag if Supabase has confirmed it
        email_confirmed = bool(
            result.get("email_confirmed_at") or result.get("email_confirmed")
        )
        if email_confirmed and not profile.email_confirmed:
            profile.email_confirmed = True
            profile.save(update_fields=["email_confirmed"])

        profile.record_login()
        return (profile, None)

    def _get_or_create_profile(
        self, supabase_uid: str, email: str, token_data: dict
    ) -> UserProfile:
        # 1. Look up by Supabase UID (normal path)
        try:
            return UserProfile.objects.select_related("tenant").get(
                supabase_uid=supabase_uid
            )
        except UserProfile.DoesNotExist:
            pass

        # 2. Look up by email (covers profiles pre-created by admin before first login)
        if email:
            try:
                profile = UserProfile.objects.select_related("tenant").get(email=email)
                if not profile.supabase_uid:
                    profile.supabase_uid = supabase_uid
                    profile.save(update_fields=["supabase_uid"])
                return profile
            except UserProfile.DoesNotExist:
                pass

        # 3. Create new profile on first login
        metadata = token_data.get("user_metadata") or {}
        return UserProfile.objects.create(
            supabase_uid=supabase_uid,
            email=email or "",
            full_name=metadata.get("full_name", ""),
            avatar_url=metadata.get("avatar_url"),
            email_confirmed=bool(token_data.get("email_confirmed_at")),
        )

    def authenticate_header(self, request):
        return "Bearer"
