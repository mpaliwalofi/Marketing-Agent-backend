"""
Authentication classes for tenant API key authentication.
"""

from rest_framework import authentication
from rest_framework import exceptions
from .services import TenantService


class TenantAPIKeyAuthentication(authentication.BaseAuthentication):
    """
    Authenticate requests using tenant API keys.
    
    The API key should be provided in the header:
    X-API-Key: <your-api-key>
    
    Or alternatively:
    Authorization: Bearer <your-api-key>
    """
    
    keyword = 'Bearer'
    
    def authenticate(self, request):
        # Check for X-API-Key header first (preferred method)
        api_key = request.META.get('HTTP_X_API_KEY')
        
        # If not found, check Authorization header
        if not api_key:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.startswith(f'{self.keyword} '):
                potential_key = auth_header[len(f'{self.keyword} '):].strip()
                
                # Skip if it looks like a JWT (has 2 dots, typical JWT structure)
                # JWT format: header.payload.signature
                if potential_key.count('.') == 2:
                    return None
                
                api_key = potential_key
        
        if not api_key:
            return None
        
        tenant = TenantService.get_tenant_by_api_key(api_key)
        
        if not tenant:
            raise exceptions.AuthenticationFailed('Invalid API key')
        
        # Attach tenant to request for use in views
        request.tenant = tenant
        
        # Return (user, auth) tuple - we don't have users, so return None
        return (None, tenant)
    
    def authenticate_header(self, request):
        """Return the authentication header format."""
        return 'X-API-Key or Bearer'
