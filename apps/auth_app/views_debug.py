"""
Debug views for troubleshooting authentication.
"""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def debug_auth(request):
    """
    Debug endpoint to check what authentication data is being received.
    """
    from .supabase_client import supabase_auth
    
    # Get all headers
    headers = dict(request.headers)
    
    # Get authorization header specifically
    auth_header = request.META.get('HTTP_AUTHORIZATION', 'Not provided')
    
    # Extract and verify token if present
    token_verification = None
    if auth_header.startswith('Bearer '):
        token = auth_header[7:].strip()
        is_valid, result = supabase_auth.verify_jwt(token)
        token_verification = {
            'valid': is_valid,
            'user_id_from_token': (result.get('sub') or result.get('id')) if is_valid else None,
            'email_from_token': result.get('email') if is_valid else None,
            'error': result.get('error') if not is_valid else None
        }
    
    # Mask sensitive info for display
    if auth_header != 'Not provided' and len(auth_header) > 20:
        # Show first 20 chars and indicate length
        auth_display = auth_header[:20] + f"... ({len(auth_header)} chars)"
    else:
        auth_display = auth_header
    
    # Check if supabase_user was attached
    supabase_user = getattr(request, 'supabase_user', None)
    tenant = getattr(request, 'tenant', None)
    
    response_data = {
        'auth_header_received': auth_display,
        'headers_count': len(headers),
        'token_verification': token_verification,
        'authenticated': supabase_user is not None,
        'supabase_user': {
            'id': str(supabase_user.id) if supabase_user else None,
            'email': supabase_user.email if supabase_user else None,
        },
        'tenant': {
            'id': str(tenant.tenant_id) if tenant else None,
            'name': tenant.name if tenant else None,
        },
        'user': str(request.user) if request.user.is_authenticated else 'Anonymous',
    }
    
    # If POST, also try to verify the token explicitly
    if request.method == 'POST':
        from .supabase_client import supabase_auth
        token = request.data.get('token')
        if token:
            is_valid, result = supabase_auth.verify_jwt(token)
            response_data['token_test'] = {
                'valid': is_valid,
                'result': result if is_valid else result.get('error')
            }
    
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_token_direct(request):
    """
    Directly verify a token without any other auth checks.
    """
    from .supabase_client import supabase_auth
    
    token = request.data.get('token')
    if not token:
        return Response({'error': 'No token provided'}, status=400)
    
    is_valid, result = supabase_auth.verify_jwt(token)
    
    if is_valid:
        # Supabase API returns 'id', JWT decode returns 'sub'
        user_id = result.get('sub') or result.get('id')
        return Response({
            'valid': True,
            'user': {
                'id': user_id,
                'email': result.get('email'),
                'role': result.get('role'),
            }
        })
    else:
        return Response({
            'valid': False,
            'error': result.get('error', 'Unknown error')
        }, status=401)
