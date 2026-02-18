"""
Services for authentication operations.
"""

import secrets
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from django.contrib.auth.models import User
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

from .models import SupabaseUser, RefreshToken, Invitation
from .supabase_client import supabase_auth
from apps.tenants.models import Tenant

logger = logging.getLogger(__name__)


class AuthService:
    """Service for authentication operations."""
    
    @staticmethod
    def register_user(email: str, password: str, tenant_id: str = None,
                      first_name: str = None, last_name: str = None,
                      redirect_url: str = None) -> Tuple[bool, Dict]:
        """
        Register a new user with Supabase.
        
        Args:
            email: User's email
            password: User's password
            tenant_id: Optional tenant ID to associate with
            first_name: User's first name
            last_name: User's last name
            redirect_url: URL to redirect after email confirmation
        
        Returns:
            Tuple of (success, data_or_error)
        """
        # Build user metadata
        user_metadata = {}
        if first_name:
            user_metadata['full_name'] = first_name
            if last_name:
                user_metadata['full_name'] += f" {last_name}"
        if tenant_id:
            user_metadata['tenant_id'] = tenant_id
        
        # Create user in Supabase
        success, result = supabase_auth.admin_create_user(
            email=email,
            password=password,
            user_metadata=user_metadata
        )
        
        if not success:
            return False, result
        
        # Get the Supabase user ID
        supabase_uid = result.get('id')
        
        # Create Django user and profile (will be linked on first login)
        # This ensures the user exists in our system
        try:
            with transaction.atomic():
                # Create Django user
                username = AuthService._generate_username(email)
                django_user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name or '',
                    last_name=last_name or '',
                    is_active=True
                )
                
                # Get tenant if provided
                tenant = None
                if tenant_id:
                    try:
                        tenant = Tenant.objects.get(tenant_id=tenant_id)
                    except Tenant.DoesNotExist:
                        pass
                
                # Create SupabaseUser profile
                supabase_user = SupabaseUser.objects.create(
                    supabase_uid=supabase_uid,
                    user=django_user,
                    tenant=tenant,
                    email=email,
                    raw_metadata=user_metadata,
                    email_confirmed=False  # Will be updated on first login
                )
                
                return True, {
                    'message': 'User registered successfully',
                    'user_id': str(supabase_user.id),
                    'supabase_uid': str(supabase_uid),
                    'email': email,
                    'tenant_id': str(tenant.tenant_id) if tenant else None
                }
        
        except Exception as e:
            # Try to clean up Supabase user if Django creation fails
            try:
                supabase_auth.admin_delete_user(supabase_uid)
            except:
                pass
            return False, {'error': f'Failed to create user profile: {str(e)}'}
    
    @staticmethod
    def login_user(email: str, password: str) -> Tuple[bool, Dict]:
        """
        Login a user with Supabase.
        
        Args:
            email: User's email
            password: User's password
        
        Returns:
            Tuple of (success, session_data_or_error)
        """
        success, result = supabase_auth.sign_in_with_password(email, password)
        
        if not success:
            logger.error(f"Supabase login failed: {result}")
            return False, result
        
        # Debug: Log the actual response structure (remove in production)
        logger.debug(f"Supabase login response keys: {list(result.keys()) if isinstance(result, dict) else 'not a dict'}")
        
        # Extract session data - Supabase returns tokens at root level
        # Response format: { "access_token": "...", "refresh_token": "...", "expires_in": 3600, "user": {...} }
        access_token = result.get('access_token')
        refresh_token = result.get('refresh_token')
        expires_in = result.get('expires_in')
        
        # Try session nested structure if root level is empty (for backward compatibility)
        if not access_token and 'session' in result:
            session = result.get('session', {})
            access_token = session.get('access_token')
            refresh_token = session.get('refresh_token')
            expires_in = session.get('expires_in')
        
        user = result.get('user', {})
        
        # Update or create SupabaseUser
        try:
            supabase_user = SupabaseUser.objects.get(supabase_uid=user.get('id'))
            supabase_user.record_login()
            
            return True, {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_in': expires_in,
                'user': {
                    'id': str(supabase_user.id),
                    'email': supabase_user.email,
                    'role': supabase_user.role,
                    'tenant_id': str(supabase_user.tenant.tenant_id) if supabase_user.tenant else None
                }
            }
        except SupabaseUser.DoesNotExist:
            return False, {'error': 'User profile not found. Please contact support.'}
    
    @staticmethod
    def refresh_token(refresh_token: str) -> Tuple[bool, Dict]:
        """
        Refresh an access token.
        
        Args:
            refresh_token: The refresh token
        
        Returns:
            Tuple of (success, session_data_or_error)
        """
        return supabase_auth.refresh_session(refresh_token)
    
    @staticmethod
    def logout_user(supabase_user: SupabaseUser) -> bool:
        """
        Logout a user (revoke tokens).
        
        Args:
            supabase_user: The SupabaseUser to logout
        
        Returns:
            True if successful
        """
        # Revoke all refresh tokens for this user
        RefreshToken.objects.filter(
            supabase_user=supabase_user,
            is_revoked=False
        ).update(is_revoked=True)
        
        return True
    
    @staticmethod
    def get_or_create_user_from_supabase(supabase_uid: str, email: str,
                                         user_data: Dict) -> SupabaseUser:
        """
        Get or create a SupabaseUser from Supabase data.
        Called during JWT authentication.
        
        Args:
            supabase_uid: Supabase user ID
            email: User's email
            user_data: Full user data from Supabase
        
        Returns:
            SupabaseUser instance
        """
        try:
            return SupabaseUser.objects.get(supabase_uid=supabase_uid)
        except SupabaseUser.DoesNotExist:
            # Create new user
            username = AuthService._generate_username(email)
            django_user = User.objects.create_user(
                username=username,
                email=email,
                first_name=user_data.get('user_metadata', {}).get('full_name', '')
            )
            
            # Get tenant from metadata
            metadata = user_data.get('user_metadata', {})
            tenant_id = metadata.get('tenant_id')
            tenant = None
            if tenant_id:
                try:
                    tenant = Tenant.objects.get(tenant_id=tenant_id)
                except Tenant.DoesNotExist:
                    pass
            
            # Determine initial agent permissions based on tenant subscription
            can_access_mark = False
            can_access_hr = False
            if tenant:
                can_access_mark = tenant.has_mark_agent_access
                can_access_hr = tenant.has_hr_agent_access
            
            return SupabaseUser.objects.create(
                supabase_uid=supabase_uid,
                user=django_user,
                tenant=tenant,
                email=email,
                can_access_mark=can_access_mark,
                can_access_hr=can_access_hr,
                raw_metadata=user_data,
                email_confirmed=user_data.get('email_confirmed', False),
                phone=user_data.get('phone'),
                avatar_url=metadata.get('avatar_url')
            )
    
    @staticmethod
    def assign_user_to_tenant(supabase_user: SupabaseUser, tenant: Tenant,
                              role: str = 'user') -> bool:
        """
        Assign a user to a tenant.
        
        Args:
            supabase_user: The user to assign
            tenant: The tenant to assign to
            role: User's role in the tenant
        
        Returns:
            True if successful
        """
        supabase_user.tenant = tenant
        supabase_user.role = role
        
        # Set agent access based on tenant subscription
        supabase_user.can_access_mark = tenant.has_mark_agent_access
        supabase_user.can_access_hr = tenant.has_hr_agent_access
        
        supabase_user.save()
        return True
    
    @staticmethod
    def create_invitation(tenant: Tenant, email: str, invited_by: SupabaseUser,
                          role: str = 'user') -> Tuple[bool, Dict]:
        """
        Create an invitation for a user to join a tenant.
        
        Args:
            tenant: The tenant to invite to
            email: Email to invite
            invited_by: User creating the invitation
            role: Role to assign
        
        Returns:
            Tuple of (success, data_or_error)
        """
        # Check if user already in tenant
        if SupabaseUser.objects.filter(email=email, tenant=tenant).exists():
            return False, {'error': 'User already in this tenant'}
        
        # Check for existing valid invitation
        existing = Invitation.objects.filter(
            tenant=tenant,
            email=email,
            is_used=False
        ).first()
        
        if existing and existing.is_valid():
            return True, {
                'message': 'Invitation already exists',
                'token': existing.token,
                'expires_at': existing.expires_at
            }
        
        # Create new invitation
        token = secrets.token_urlsafe(32)
        invitation = Invitation.objects.create(
            tenant=tenant,
            email=email,
            invited_by=invited_by,
            role=role,
            token=token,
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        return True, {
            'message': 'Invitation created',
            'token': invitation.token,
            'expires_at': invitation.expires_at
        }
    
    @staticmethod
    def accept_invitation(token: str, supabase_user: SupabaseUser) -> Tuple[bool, Dict]:
        """
        Accept an invitation and join a tenant.
        
        Args:
            token: Invitation token
            supabase_user: The user accepting the invitation
        
        Returns:
            Tuple of (success, data_or_error)
        """
        try:
            invitation = Invitation.objects.get(token=token)
        except Invitation.DoesNotExist:
            return False, {'error': 'Invalid invitation token'}
        
        if not invitation.is_valid():
            return False, {'error': 'Invitation has expired or been used'}
        
        if invitation.email != supabase_user.email:
            return False, {'error': 'Invitation email does not match'}
        
        # Assign user to tenant
        AuthService.assign_user_to_tenant(
            supabase_user=supabase_user,
            tenant=invitation.tenant,
            role=invitation.role
        )
        
        # Mark invitation as used
        invitation.is_used = True
        invitation.used_at = timezone.now()
        invitation.save()
        
        return True, {
            'message': f'Joined {invitation.tenant.name}',
            'tenant_id': str(invitation.tenant.tenant_id),
            'role': invitation.role
        }
    
    @staticmethod
    def _generate_username(email: str) -> str:
        """Generate a unique username from email."""
        base = email.split('@')[0][:30]
        username = base
        counter = 1
        while User.objects.filter(username=username).exists():
            suffix = str(counter)
            username = f"{base[:30-len(suffix)]}{suffix}"
            counter += 1
        return username


class UserPermissionService:
    """Service for checking user permissions."""
    
    @staticmethod
    def can_access_agent(supabase_user: SupabaseUser, agent_type: str) -> bool:
        """
        Check if user can access an agent.
        
        Args:
            supabase_user: The user to check
            agent_type: 'mark' or 'hr'
        
        Returns:
            True if access is allowed
        """
        return supabase_user.has_agent_access(agent_type)
    
    @staticmethod
    def is_tenant_admin(supabase_user: SupabaseUser) -> bool:
        """Check if user is a tenant admin."""
        return supabase_user.role == 'admin'
    
    @staticmethod
    def can_manage_users(supabase_user: SupabaseUser) -> bool:
        """Check if user can manage other users."""
        return supabase_user.role in ['admin', 'manager']
    
    @staticmethod
    def get_accessible_agents(supabase_user: SupabaseUser) -> list:
        """
        Get list of agents the user can access.
        
        Returns:
            List of agent types
        """
        agents = []
        if supabase_user.has_agent_access('mark'):
            agents.append('mark')
        if supabase_user.has_agent_access('hr'):
            agents.append('hr')
        return agents
