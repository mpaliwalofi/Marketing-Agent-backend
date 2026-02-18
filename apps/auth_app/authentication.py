"""
Django REST Framework authentication classes for Supabase.
"""

from rest_framework import authentication
from rest_framework import exceptions
from django.contrib.auth.models import User
from django.db import transaction
from .supabase_client import supabase_auth
from .models import SupabaseUser, LoginAttempt
from apps.tenants.models import Tenant
import logging

logger = logging.getLogger(__name__)


class SupabaseJWTAuthentication(authentication.BaseAuthentication):
    """
    Authenticate requests using Supabase JWT tokens.
    
    The token should be provided in the Authorization header:
    Authorization: Bearer <supabase-jwt-token>
    
    This authentication class:
    1. Verifies the JWT token with Supabase
    2. Gets or creates the Django user
    3. Links the user to their tenant
    4. Attaches user and tenant to the request
    """
    
    keyword = 'Bearer'
    
    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode('utf-8')
        
        if not auth_header:
            return None
        
        if not auth_header.startswith(f'{self.keyword} '):
            return None
        
        token = auth_header[len(f'{self.keyword} '):].strip()
        
        if not token:
            return None
        
        return self.authenticate_credentials(request, token)
    
    def authenticate_credentials(self, request, token):
        """
        Verify the Supabase token and return user.
        """
        # Verify token with Supabase
        is_valid, result = supabase_auth.verify_jwt(token)
        
        if not is_valid:
            error_msg = result.get('error', 'Invalid token')
            self._log_attempt(request, None, False, error_msg)
            raise exceptions.AuthenticationFailed(error_msg)
        
        # Extract user info from token payload
        user_data = result
        # Supabase API returns 'id', JWT decode returns 'sub'
        supabase_uid = user_data.get('sub') or user_data.get('id')
        email = user_data.get('email')
        
        if not supabase_uid:
            logger.error(f"No user ID found in token data. Keys: {list(user_data.keys())}")
            raise exceptions.AuthenticationFailed('Invalid token: no user ID')
        
        # Get or create user
        try:
            supabase_user = self._get_or_create_user(
                supabase_uid=supabase_uid,
                email=email,
                user_data=user_data,
                request=request
            )
        except Exception as e:
            logger.error(f"Failed to get/create user: {e}")
            raise exceptions.AuthenticationFailed('User authentication failed')
        
        if not supabase_user.is_active:
            self._log_attempt(request, email, False, 'User account is disabled')
            raise exceptions.AuthenticationFailed('User account is disabled')
        
        # Log successful login
        self._log_attempt(request, email, True)
        supabase_user.record_login()
        
        # Attach to request
        request.supabase_user = supabase_user
        request.tenant = supabase_user.tenant
        
        return (supabase_user.user, supabase_user)
    
    def _get_or_create_user(self, supabase_uid, email, user_data, request):
        """
        Get or create Django user and SupabaseUser profile.
        """
        with transaction.atomic():
            supabase_user = None
            
            # Try 1: Get by Supabase UID
            try:
                supabase_user = SupabaseUser.objects.select_related('user', 'tenant').get(
                    supabase_uid=supabase_uid
                )
            except SupabaseUser.DoesNotExist:
                pass
            
            # Try 2: Get by email (user might have been created before with null UID)
            if not supabase_user and email:
                try:
                    supabase_user = SupabaseUser.objects.select_related('user', 'tenant').get(
                        email=email
                    )
                    # Update the supabase_uid if it was null
                    if not supabase_user.supabase_uid:
                        supabase_user.supabase_uid = supabase_uid
                        supabase_user.save(update_fields=['supabase_uid'])
                except SupabaseUser.DoesNotExist:
                    pass
            
            # If found, update and return
            if supabase_user:
                # Update user info if changed
                if email and supabase_user.email != email:
                    supabase_user.email = email
                    supabase_user.user.email = email
                    supabase_user.user.save(update_fields=['email'])
                
                # Update metadata
                supabase_user.raw_metadata = user_data
                supabase_user.email_confirmed = user_data.get('email_confirmed', False)
                supabase_user.save()
                
                return supabase_user
            
            # Not found, create new user
            # Create Django user
            username = self._generate_username(email)
            django_user = User.objects.create_user(
                username=username,
                email=email or '',
                first_name=user_data.get('user_metadata', {}).get('full_name', '')
            )
            
            # Get tenant from metadata or create default
            tenant = self._get_tenant_from_metadata(user_data)
            
            # Create SupabaseUser profile
            supabase_user = SupabaseUser.objects.create(
                supabase_uid=supabase_uid,
                user=django_user,
                tenant=tenant,
                email=email,
                raw_metadata=user_data,
                email_confirmed=user_data.get('email_confirmed', False),
                phone=user_data.get('phone'),
                avatar_url=user_data.get('user_metadata', {}).get('avatar_url')
            )
            
            return supabase_user
    
    def _get_tenant_from_metadata(self, user_data):
        """
        Get tenant from user metadata.
        If tenant_id is in metadata, look it up. Otherwise return None.
        """
        metadata = user_data.get('user_metadata', {})
        tenant_id = metadata.get('tenant_id')
        
        if tenant_id:
            try:
                return Tenant.objects.get(tenant_id=tenant_id)
            except Tenant.DoesNotExist:
                pass
        
        return None
    
    def _generate_username(self, email):
        """Generate a unique username from email."""
        if email:
            base_username = email.split('@')[0][:30]
        else:
            base_username = 'user'
        
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            suffix = str(counter)
            username = f"{base_username[:30-len(suffix)]}{suffix}"
            counter += 1
        
        return username
    
    def _log_attempt(self, request, email, success, error_message=None):
        """Log login attempt."""
        try:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')
            
            LoginAttempt.objects.create(
                email=email or 'unknown',
                success=success,
                error_message=error_message,
                ip_address=ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )
        except Exception as e:
            logger.error(f"Failed to log login attempt: {e}")
    
    def authenticate_header(self, request):
        return 'Bearer'


class SupabaseSessionAuthentication(authentication.SessionAuthentication):
    """
    Session authentication that also checks SupabaseUser.
    Used for admin interface and browsable API.
    """
    
    def authenticate(self, request):
        result = super().authenticate(request)
        
        if result is None:
            return None
        
        user, _ = result
        
        # Check if user has Supabase profile
        try:
            supabase_user = user.supabase_profile
            if not supabase_user.is_active:
                raise exceptions.AuthenticationFailed('Supabase user is inactive')
            
            request.supabase_user = supabase_user
            request.tenant = supabase_user.tenant
        except SupabaseUser.DoesNotExist:
            # Allow non-Supabase users (admin users) but don't attach tenant
            request.supabase_user = None
            request.tenant = None
        
        return result


class APIKeyOrSupabaseAuth(authentication.BaseAuthentication):
    """
    Authentication that accepts either:
    - Supabase JWT token (for web users)
    - Tenant API Key (for service integrations)
    
    Priority: Supabase JWT > API Key
    """
    
    def authenticate(self, request):
        # Try Supabase JWT first
        supabase_auth = SupabaseJWTAuthentication()
        result = supabase_auth.authenticate(request)
        
        if result:
            return result
        
        # Fall back to API key
        from apps.tenants.authentication import TenantAPIKeyAuthentication
        api_key_auth = TenantAPIKeyAuthentication()
        return api_key_auth.authenticate(request)
