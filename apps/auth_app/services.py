"""
Authentication service — thin wrapper around supabase_auth operations.
"""

import logging
from typing import Dict, Tuple

from .models import UserProfile
from .supabase_client import supabase_auth

logger = logging.getLogger(__name__)


class AuthService:

    @staticmethod
    def register_user(
        email: str, password: str, full_name: str = ""
    ) -> Tuple[bool, Dict]:
        """
        Register a new user via Supabase sign-up.
        Supabase sends an email confirmation link; the UserProfile is created
        automatically on the user's first authenticated request.
        """
        if UserProfile.objects.filter(email=email).exists():
            return False, {"error": "Email already registered."}

        metadata = {"full_name": full_name} if full_name else {}
        success, result = supabase_auth.sign_up(email, password, metadata)

        if not success:
            return False, result

        # Extract user ID from the Supabase response
        user_data = result.get("user") or result
        supabase_uid = user_data.get("id")

        # Pre-create the profile so admins can find the user before first login
        if supabase_uid:
            UserProfile.objects.get_or_create(
                supabase_uid=supabase_uid,
                defaults={"email": email, "full_name": full_name},
            )

        return True, {
            "message": "Registration successful. Please verify your email before logging in.",
            "email": email,
        }

    @staticmethod
    def login_user(email: str, password: str) -> Tuple[bool, Dict]:
        """
        Authenticate via Supabase and return JWT tokens + user info.
        """
        success, result = supabase_auth.sign_in_with_password(email, password)
        if not success:
            return False, result

        access_token = result.get("access_token")
        refresh_token = result.get("refresh_token")
        expires_in = result.get("expires_in", 3600)
        user_data = result.get("user", {})

        if not user_data.get("email_confirmed_at"):
            return False, {
                "error": "Email not verified. Please check your inbox and confirm your account.",
                "code": "email_not_verified",
            }

        supabase_uid = user_data.get("id")
        metadata = user_data.get("user_metadata") or {}

        # Upsert the local profile
        profile, _ = UserProfile.objects.get_or_create(
            supabase_uid=supabase_uid,
            defaults={"email": email, "full_name": metadata.get("full_name", "")},
        )

        if not profile.email_confirmed:
            profile.email_confirmed = True
            profile.save(update_fields=["email_confirmed"])

        profile.record_login()

        return True, {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "user": {
                "id": str(profile.id),
                "email": profile.email,
                "full_name": profile.full_name,
                "role": profile.role,
                "subscription_type": profile.tenant.subscription_type if profile.tenant else None,
                "subscription_status": profile.tenant.subscription_status if profile.tenant else None,
                "can_access_mark": profile.can_access_mark,
                "can_access_hr": profile.can_access_hr,
            },
        }

    @staticmethod
    def refresh_token(refresh_token: str) -> Tuple[bool, Dict]:
        return supabase_auth.refresh_session(refresh_token)

    @staticmethod
    def logout_user(access_token: str) -> bool:
        """Invalidate the Supabase session (best-effort)."""
        supabase_auth.sign_out(access_token)
        return True

    @staticmethod
    def request_password_reset(email: str) -> Tuple[bool, Dict]:
        return supabase_auth.send_password_reset(email)
