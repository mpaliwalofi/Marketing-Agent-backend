"""
Supabase client configuration and JWT verification.
"""

import os
import jwt
import requests
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class SupabaseConfig:
    """Supabase configuration from environment variables."""
    
    SUPABASE_URL = os.getenv('SUPABASE_URL', '')
    SUPABASE_ANON_KEY = os.getenv('SUPABASE_ANON_KEY', '')
    SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY', '')
    SUPABASE_JWT_SECRET = os.getenv('SUPABASE_JWT_SECRET', '')
    
    @classmethod
    def is_configured(cls):
        """Check if Supabase is properly configured."""
        return bool(cls.SUPABASE_URL and cls.SUPABASE_ANON_KEY)


class SupabaseAuth:
    """
    Supabase Authentication client.
    Handles JWT verification and user authentication.
    """
    
    def __init__(self):
        self.supabase_url = SupabaseConfig.SUPABASE_URL.rstrip('/')
        self.anon_key = SupabaseConfig.SUPABASE_ANON_KEY
        self.service_key = SupabaseConfig.SUPABASE_SERVICE_KEY
        self.jwt_secret = SupabaseConfig.SUPABASE_JWT_SECRET
        
        self.auth_url = f"{self.supabase_url}/auth/v1"
        self.rest_url = f"{self.supabase_url}/rest/v1"
    
    def verify_jwt(self, token: str) -> Tuple[bool, Dict]:
        """
        Verify a Supabase JWT token.
        
        Supports:
        - HS256 (symmetric) - verify with JWT_SECRET locally
        - ES256 (asymmetric) - verify via Supabase API (requires public key)
        - RS256 (asymmetric) - verify via Supabase API
        
        Args:
            token: The JWT token to verify
        
        Returns:
            Tuple of (is_valid, payload_or_error)
        """
        # First, decode header to check algorithm without verification
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get('alg', 'HS256')
            logger.debug(f"JWT algorithm: {alg}")
            
            # If it's HS256 and we have a secret, try local verification
            if alg == 'HS256' and self.jwt_secret and len(self.jwt_secret) > 10:
                try:
                    payload = jwt.decode(
                        token,
                        self.jwt_secret,
                        algorithms=['HS256'],
                        audience='authenticated'
                    )
                    return True, payload
                except jwt.InvalidTokenError:
                    # Fall through to API verification
                    pass
            
            # For ES256, RS256, or if local verification failed, use Supabase API
            # ES256/RS256 require public keys which we get from Supabase
        except Exception:
            # If we can't decode header, try API verification anyway
            pass
        
        # Verify by calling Supabase user endpoint (works for all token types)
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'apikey': self.anon_key
            }
            
            logger.debug(f"Verifying token via Supabase API: {self.auth_url}/user")
            
            response = requests.get(
                f"{self.auth_url}/user",
                headers=headers,
                timeout=10
            )
            
            logger.debug(f"Supabase API response: {response.status_code}")
            
            if response.status_code == 200:
                return True, response.json()
            elif response.status_code == 401:
                error_data = response.json() if response.text else {'message': 'Unknown error'}
                return False, {'error': f"Token invalid: {error_data.get('message', 'Unauthorized')}"}
            else:
                return False, {'error': f"Verification failed: {response.status_code}", 'details': response.text[:200]}
        
        except requests.exceptions.Timeout:
            return False, {'error': 'Verification request timed out'}
        except requests.exceptions.RequestException as e:
            return False, {'error': f'Verification failed: {str(e)}'}
        except Exception as e:
            return False, {'error': f'Unexpected error: {str(e)}'}
    
    def get_user(self, token: str) -> Tuple[bool, Dict]:
        """
        Get user information from Supabase.
        
        Args:
            token: The JWT token
        
        Returns:
            Tuple of (success, user_data_or_error)
        """
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'apikey': self.anon_key
            }
            
            response = requests.get(
                f"{self.auth_url}/user",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, {'error': response.text}
        
        except Exception as e:
            return False, {'error': str(e)}
    
    def refresh_session(self, refresh_token: str) -> Tuple[bool, Dict]:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: The refresh token
        
        Returns:
            Tuple of (success, session_data_or_error)
        """
        try:
            headers = {
                'apikey': self.anon_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.auth_url}/token?grant_type=refresh_token",
                headers=headers,
                json={'refresh_token': refresh_token},
                timeout=10
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, {'error': response.text}
        
        except Exception as e:
            return False, {'error': str(e)}
    
    def admin_create_user(self, email: str, password: str, 
                          user_metadata: Dict = None) -> Tuple[bool, Dict]:
        """
        Create a user using the service role key (admin only).
        
        Args:
            email: User's email
            password: User's password
            user_metadata: Additional user metadata
        
        Returns:
            Tuple of (success, user_data_or_error)
        """
        try:
            headers = {
                'Authorization': f'Bearer {self.service_key}',
                'apikey': self.anon_key,
                'Content-Type': 'application/json'
            }
            
            data = {
                'email': email,
                'password': password,
                'email_confirm': True
            }
            
            if user_metadata:
                data['user_metadata'] = user_metadata
            
            response = requests.post(
                f"{self.auth_url}/admin/users",
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                return True, response.json()
            else:
                return False, {'error': response.text}
        
        except Exception as e:
            return False, {'error': str(e)}
    
    def admin_delete_user(self, user_id: str) -> Tuple[bool, Dict]:
        """
        Delete a user using the service role key (admin only).
        
        Args:
            user_id: The user's UUID
        
        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            headers = {
                'Authorization': f'Bearer {self.service_key}',
                'apikey': self.anon_key
            }
            
            response = requests.delete(
                f"{self.auth_url}/admin/users/{user_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return True, {'message': 'User deleted'}
            else:
                return False, {'error': response.text}
        
        except Exception as e:
            return False, {'error': str(e)}
    
    def sign_in_with_password(self, email: str, password: str) -> Tuple[bool, Dict]:
        """
        Sign in a user with email and password.
        This is used server-side for testing/admin purposes.
        Client apps should use Supabase client directly.
        
        Args:
            email: User's email
            password: User's password
        
        Returns:
            Tuple of (success, session_data_or_error)
        """
        try:
            headers = {
                'apikey': self.anon_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.auth_url}/token?grant_type=password",
                headers=headers,
                json={'email': email, 'password': password},
                timeout=10
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, {'error': response.text}
        
        except Exception as e:
            return False, {'error': str(e)}


# Global instance
supabase_auth = SupabaseAuth()
