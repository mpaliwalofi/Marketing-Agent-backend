"""
Views for authentication endpoints.
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout
from django.db import transaction
import logging

from .models import SupabaseUser, Invitation
from .serializers import (
    RegisterSerializer, LoginSerializer, TokenRefreshSerializer,
    UserProfileSerializer, UserUpdateSerializer, InvitationSerializer,
    AcceptInvitationSerializer
)
from .services import AuthService, UserPermissionService
from .permissions import IsSupabaseUser, IsTenantAdmin, HasTenantAccess
from .authentication import SupabaseJWTAuthentication

logger = logging.getLogger(__name__)


# =============================================================================
# Registration & Login
# =============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """
    Register a new user.
    
    Request body:
    {
        "email": "user@example.com",
        "password": "securepassword",
        "first_name": "John",
        "last_name": "Doe",
        "tenant_id": "optional-tenant-id"
    }
    """
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'error': 'Invalid data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    data = serializer.validated_data
    
    success, result = AuthService.register_user(
        email=data['email'],
        password=data['password'],
        tenant_id=data.get('tenant_id'),
        first_name=data.get('first_name'),
        last_name=data.get('last_name')
    )
    
    if not success:
        return Response({
            'success': False,
            'error': result.get('error', 'Registration failed')
        }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({
        'success': True,
        'message': 'Registration successful. Please check your email to confirm your account.',
        'data': {
            'user_id': result.get('user_id'),
            'email': result.get('email')
        }
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """
    Login a user.
    
    Request body:
    {
        "email": "user@example.com",
        "password": "securepassword"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "access_token": "...",
            "refresh_token": "...",
            "expires_in": 3600,
            "user": {
                "id": "...",
                "email": "...",
                "role": "...",
                "tenant_id": "..."
            }
        }
    }
    """
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'error': 'Invalid data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    data = serializer.validated_data
    
    success, result = AuthService.login_user(
        email=data['email'],
        password=data['password']
    )
    
    if not success:
        return Response({
            'success': False,
            'error': result.get('error', 'Login failed')
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response({
        'success': True,
        'message': 'Login successful',
        'data': result
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """
    Refresh an access token using a refresh token.
    
    Request body:
    {
        "refresh_token": "..."
    }
    """
    serializer = TokenRefreshSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'error': 'Invalid data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    success, result = AuthService.refresh_token(serializer.validated_data['refresh_token'])
    
    if not success:
        return Response({
            'success': False,
            'error': result.get('error', 'Token refresh failed')
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response({
        'success': True,
        'data': {
            'access_token': result.get('access_token'),
            'refresh_token': result.get('refresh_token'),
            'expires_in': result.get('expires_in')
        }
    })


@api_view(['POST'])
@permission_classes([IsSupabaseUser])
def logout(request):
    """
    Logout the current user.
    Requires authentication.
    """
    supabase_user = request.supabase_user
    
    AuthService.logout_user(supabase_user)
    
    return Response({
        'success': True,
        'message': 'Logout successful'
    })


# =============================================================================
# User Profile
# =============================================================================

@api_view(['GET'])
@permission_classes([IsSupabaseUser])
def profile(request):
    """
    Get current user profile.
    """
    supabase_user = request.supabase_user
    
    serializer = UserProfileSerializer(supabase_user)
    
    # Add accessible agents
    data = serializer.data
    data['accessible_agents'] = UserPermissionService.get_accessible_agents(supabase_user)
    
    return Response({
        'success': True,
        'data': data
    })


@api_view(['PUT', 'PATCH'])
@permission_classes([IsSupabaseUser])
def update_profile(request):
    """
    Update current user profile.
    """
    supabase_user = request.supabase_user
    
    serializer = UserUpdateSerializer(supabase_user, data=request.data, partial=True)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'error': 'Invalid data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer.save()
    
    return Response({
        'success': True,
        'message': 'Profile updated',
        'data': UserProfileSerializer(supabase_user).data
    })


# =============================================================================
# Agent Access
# =============================================================================

@api_view(['GET'])
@permission_classes([IsSupabaseUser])
def agent_access(request):
    """
    Get agent access information for the current user.
    """
    supabase_user = request.supabase_user
    tenant = supabase_user.tenant
    
    access_info = {
        'user': {
            'id': str(supabase_user.id),
            'email': supabase_user.email,
            'role': supabase_user.role
        },
        'tenant': {
            'id': str(tenant.tenant_id) if tenant else None,
            'name': tenant.name if tenant else None,
            'subscribed_agents': tenant.subscribed_agents if tenant else None,
            'status': tenant.status if tenant else None
        } if tenant else None,
        'access': {
            'mark': supabase_user.has_agent_access('mark'),
            'hr': supabase_user.has_agent_access('hr')
        },
        'permissions': {
            'is_admin': UserPermissionService.is_tenant_admin(supabase_user),
            'can_manage_users': UserPermissionService.can_manage_users(supabase_user)
        }
    }
    
    return Response({
        'success': True,
        'data': access_info
    })


# =============================================================================
# Invitations
# =============================================================================

class InvitationListCreateView(APIView):
    """List and create invitations."""
    
    permission_classes = [IsSupabaseUser, IsTenantAdmin]
    
    def get(self, request):
        """List invitations for the user's tenant."""
        tenant = request.supabase_user.tenant
        
        if not tenant:
            return Response({
                'success': False,
                'error': 'No tenant associated'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        invitations = Invitation.objects.filter(tenant=tenant)
        
        # Filter by status
        status_filter = request.query_params.get('status')
        if status_filter == 'pending':
            invitations = invitations.filter(is_used=False)
        elif status_filter == 'used':
            invitations = invitations.filter(is_used=True)
        
        serializer = InvitationSerializer(invitations, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data
        })
    
    def post(self, request):
        """Create a new invitation."""
        tenant = request.supabase_user.tenant
        
        if not tenant:
            return Response({
                'success': False,
                'error': 'No tenant associated'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = InvitationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        success, result = AuthService.create_invitation(
            tenant=tenant,
            email=serializer.validated_data['email'],
            invited_by=request.supabase_user,
            role=serializer.validated_data.get('role', 'user')
        )
        
        if not success:
            return Response({
                'success': False,
                'error': result.get('error', 'Failed to create invitation')
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': True,
            'message': 'Invitation created',
            'data': result
        }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([IsSupabaseUser])
def accept_invitation(request):
    """
    Accept an invitation to join a tenant.
    
    Request body:
    {
        "token": "invitation-token"
    }
    """
    serializer = AcceptInvitationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'error': 'Invalid data',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    success, result = AuthService.accept_invitation(
        token=serializer.validated_data['token'],
        supabase_user=request.supabase_user
    )
    
    if not success:
        return Response({
            'success': False,
            'error': result.get('error', 'Failed to accept invitation')
        }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({
        'success': True,
        'message': result.get('message', 'Invitation accepted'),
        'data': {
            'tenant_id': result.get('tenant_id'),
            'role': result.get('role')
        }
    })


# =============================================================================
# Session Validation
# =============================================================================

@api_view(['GET'])
@permission_classes([IsSupabaseUser])
def validate_session(request):
    """
    Validate the current session and return user info.
    Useful for checking if token is still valid on app load.
    """
    supabase_user = request.supabase_user
    
    return Response({
        'success': True,
        'data': {
            'valid': True,
            'user': {
                'id': str(supabase_user.id),
                'email': supabase_user.email,
                'role': supabase_user.role,
                'tenant_id': str(supabase_user.tenant.tenant_id) if supabase_user.tenant else None
            }
        }
    })


# =============================================================================
# Password Reset
# =============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def request_password_reset(request):
    """
    Request a password reset email.
    This is handled by Supabase, we just proxy the request.
    
    Request body:
    {
        "email": "user@example.com"
    }
    """
    email = request.data.get('email')
    
    if not email:
        return Response({
            'success': False,
            'error': 'Email is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # In production, this would call Supabase to send reset email
    # For now, just acknowledge
    return Response({
        'success': True,
        'message': 'If an account exists with this email, a password reset link has been sent.'
    })
