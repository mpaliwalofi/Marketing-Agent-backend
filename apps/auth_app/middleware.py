"""
Middleware for Supabase JWT authentication.
"""

from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
import logging

from .supabase_client import supabase_auth
from .services import AuthService

logger = logging.getLogger(__name__)


class SupabaseAuthMiddleware(MiddlewareMixin):
    """
    Middleware that authenticates requests using Supabase JWT.
    
    This middleware:
    1. Checks for Authorization header
    2. Verifies the JWT token with Supabase
    3. Attaches the user to the request
    
    Excluded paths (no auth required):
    - /api/auth/login/
    - /api/auth/register/
    - /api/auth/refresh/
    - /api/auth/password/reset/
    - /admin/
    - /static/
    - /health/
    """
    
    EXCLUDED_PATHS = [
        '/api/auth/login/',
        '/api/auth/register/',
        '/api/auth/refresh/',
        '/api/auth/password/reset/',
        '/api/tenants/validate-key/',
        '/admin/',
        '/static/',
        '/health/',
        '/api/waitlist/',
        '/api/chat/',
    ]
    
    EXCLUDED_PREFIXES = [
        '/admin/',
        '/static/',
        '/media/',
    ]
    
    def process_request(self, request):
        """Process incoming request."""
        path = request.path_info
        
        # Check if path is excluded
        if self._is_excluded(path):
            return None
        
        # Check for Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header:
            # No auth header - allow anonymous (view will check permissions)
            return None
        
        # Try to authenticate with Supabase
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            
            try:
                is_valid, result = supabase_auth.verify_jwt(token)
                
                if is_valid:
                    # Get or create user
                    # Supabase API returns 'id', JWT decode returns 'sub'
                    supabase_uid = result.get('sub') or result.get('id')
                    email = result.get('email')
                    
                    if not supabase_uid:
                        logger.warning("No user ID found in token")
                        return None
                    
                    supabase_user = AuthService.get_or_create_user_from_supabase(
                        supabase_uid=supabase_uid,
                        email=email,
                        user_data=result
                    )
                    
                    # Attach to request
                    request.supabase_user = supabase_user
                    request.tenant = supabase_user.tenant
                    request.user = supabase_user.user
                    
            except Exception as e:
                logger.error(f"Auth middleware error: {e}")
                # Continue without authentication - view will handle it
        
        return None
    
    def _is_excluded(self, path):
        """Check if path is excluded from authentication."""
        # Check exact matches
        if path in self.EXCLUDED_PATHS:
            return True
        
        # Check prefixes
        for prefix in self.EXCLUDED_PREFIXES:
            if path.startswith(prefix):
                return True
        
        return False


class TenantMiddleware(MiddlewareMixin):
    """
    Middleware that ensures tenant context is available.
    Must be placed after SupabaseAuthMiddleware.
    """
    
    def process_request(self, request):
        """Attach tenant context to request."""
        # If supabase_user is set, tenant is already attached
        if hasattr(request, 'supabase_user') and request.supabase_user:
            request.tenant = request.supabase_user.tenant
        else:
            request.tenant = None
        
        return None


class CORSMiddleware:
    """
    Simple CORS middleware for handling cross-origin requests.
    This is a complement to django-cors-headers.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add CORS headers
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, X-API-Key'
        response['Access-Control-Expose-Headers'] = 'X-RateLimit-Limit, X-RateLimit-Remaining'
        
        return response


class RateLimitMiddleware:
    """
    Middleware for rate limiting based on user or IP.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Get identifier (user ID if authenticated, IP otherwise)
        if hasattr(request, 'supabase_user') and request.supabase_user:
            identifier = f"user:{request.supabase_user.id}"
        else:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')
            identifier = f"ip:{ip}"
        
        # Store identifier for use in views
        request.rate_limit_key = identifier
        
        response = self.get_response(request)
        
        return response
