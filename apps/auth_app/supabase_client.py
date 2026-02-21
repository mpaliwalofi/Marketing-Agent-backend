"""
Supabase Auth HTTP client.

All token/session management (sign-up, sign-in, sign-out, refresh, JWT
verification) is delegated to Supabase. Django only stores the user profile.
"""

import os
import jwt
import requests
import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class SupabaseAuth:
    """Thin wrapper around the Supabase Auth REST API."""

    def __init__(self):
        self.url = os.getenv("SUPABASE_URL", "").rstrip("/")
        self.anon_key = os.getenv("SUPABASE_ANON_KEY", "")
        self.service_key = os.getenv("SUPABASE_SERVICE_KEY", "")
        self.jwt_secret = os.getenv("SUPABASE_JWT_SECRET", "")
        self.auth_url = f"{self.url}/auth/v1"

    # ------------------------------------------------------------------ #
    # JWT verification                                                      #
    # ------------------------------------------------------------------ #

    def verify_jwt(self, token: str) -> Tuple[bool, Dict]:
        """
        Verify a Supabase JWT token and return its payload.

        Tries local HS256 verification first (fast, no network call).
        Falls back to Supabase API verification for other algorithms or
        when SUPABASE_JWT_SECRET is not configured.
        """
        # Attempt fast local verification if secret is available
        if self.jwt_secret:
            try:
                header = jwt.get_unverified_header(token)
                if header.get("alg") == "HS256":
                    payload = jwt.decode(
                        token,
                        self.jwt_secret,
                        algorithms=["HS256"],
                        audience="authenticated",
                    )
                    return True, payload
            except jwt.ExpiredSignatureError:
                return False, {"error": "Token has expired"}
            except jwt.InvalidTokenError:
                pass  # fall through to API verification

        # API-based verification (works for all algorithms)
        return self._verify_via_api(token)

    def _verify_via_api(self, token: str) -> Tuple[bool, Dict]:
        try:
            response = requests.get(
                f"{self.auth_url}/user",
                headers={"Authorization": f"Bearer {token}", "apikey": self.anon_key},
                timeout=10,
            )
            if response.status_code == 200:
                return True, response.json()
            elif response.status_code == 401:
                msg = response.json().get("message", "Unauthorized") if response.text else "Unauthorized"
                return False, {"error": f"Token invalid: {msg}"}
            else:
                return False, {"error": f"Verification failed ({response.status_code})"}
        except requests.exceptions.Timeout:
            return False, {"error": "Supabase verification timed out"}
        except requests.exceptions.RequestException as exc:
            return False, {"error": f"Supabase request failed: {exc}"}

    # ------------------------------------------------------------------ #
    # Auth operations                                                        #
    # ------------------------------------------------------------------ #

    def sign_up(self, email: str, password: str, user_metadata: Dict = None) -> Tuple[bool, Dict]:
        """
        Register a new user. Supabase sends a confirmation email.
        Returns (True, user_data) or (False, error_dict).
        """
        body = {"email": email, "password": password}
        if user_metadata:
            body["data"] = user_metadata  # Supabase v2 uses 'data' for user_metadata on sign-up

        try:
            response = requests.post(
                f"{self.auth_url}/signup",
                headers={"apikey": self.anon_key, "Content-Type": "application/json"},
                json=body,
                timeout=10,
            )
            data = response.json() if response.text else {}
            if response.status_code in (200, 201):
                return True, data
            error_msg = data.get("msg") or data.get("message") or data.get("error_description") or "Registration failed"
            return False, {"error": error_msg}
        except requests.exceptions.RequestException as exc:
            return False, {"error": str(exc)}

    def sign_in_with_password(self, email: str, password: str) -> Tuple[bool, Dict]:
        """
        Sign in with email + password.
        Returns Supabase session: { access_token, refresh_token, expires_in, user }.
        """
        try:
            response = requests.post(
                f"{self.auth_url}/token?grant_type=password",
                headers={"apikey": self.anon_key, "Content-Type": "application/json"},
                json={"email": email, "password": password},
                timeout=10,
            )
            data = response.json() if response.text else {}
            if response.status_code == 200:
                return True, data
            error_msg = data.get("error_description") or data.get("msg") or data.get("message") or "Login failed"
            return False, {"error": error_msg}
        except requests.exceptions.RequestException as exc:
            return False, {"error": str(exc)}

    def sign_out(self, access_token: str) -> bool:
        """
        Invalidate the user's session on Supabase.
        Returns True on success (or if token is already invalid).
        """
        try:
            requests.post(
                f"{self.auth_url}/logout",
                headers={"Authorization": f"Bearer {access_token}", "apikey": self.anon_key},
                timeout=10,
            )
        except requests.exceptions.RequestException:
            pass  # Best-effort; client will discard token regardless
        return True

    def refresh_session(self, refresh_token: str) -> Tuple[bool, Dict]:
        """Exchange a refresh token for a new access token."""
        try:
            response = requests.post(
                f"{self.auth_url}/token?grant_type=refresh_token",
                headers={"apikey": self.anon_key, "Content-Type": "application/json"},
                json={"refresh_token": refresh_token},
                timeout=10,
            )
            data = response.json() if response.text else {}
            if response.status_code == 200:
                return True, data
            error_msg = data.get("error_description") or data.get("msg") or "Refresh failed"
            return False, {"error": error_msg}
        except requests.exceptions.RequestException as exc:
            return False, {"error": str(exc)}

    def send_password_reset(self, email: str, redirect_url: str = None) -> Tuple[bool, Dict]:
        """Trigger Supabase password-reset email."""
        body = {"email": email}
        if redirect_url:
            body["redirect_to"] = redirect_url
        try:
            response = requests.post(
                f"{self.auth_url}/recover",
                headers={"apikey": self.anon_key, "Content-Type": "application/json"},
                json=body,
                timeout=10,
            )
            if response.status_code in (200, 204):
                return True, {}
            return False, {"error": "Failed to send reset email"}
        except requests.exceptions.RequestException as exc:
            return False, {"error": str(exc)}

    def admin_create_user(self, email: str, password: str, user_metadata: Dict = None, email_confirm: bool = True) -> Tuple[bool, Dict]:
        """Create a user via service role (bypasses email confirmation)."""
        body = {"email": email, "password": password, "email_confirm": email_confirm}
        if user_metadata:
            body["user_metadata"] = user_metadata
        try:
            response = requests.post(
                f"{self.auth_url}/admin/users",
                headers={
                    "Authorization": f"Bearer {self.service_key}",
                    "apikey": self.anon_key,
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=10,
            )
            data = response.json() if response.text else {}
            if response.status_code in (200, 201):
                return True, data
            return False, {"error": data.get("msg") or data.get("message") or "Admin create failed"}
        except requests.exceptions.RequestException as exc:
            return False, {"error": str(exc)}


# Module-level singleton
supabase_auth = SupabaseAuth()
