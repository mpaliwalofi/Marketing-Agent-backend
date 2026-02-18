"""
Authentication models for Supabase integration.
Links Supabase users with Django users and tenants.
"""

from django.db import models
from django.contrib.auth.models import User
from django.core.validators import EmailValidator
import uuid


class SupabaseUser(models.Model):
    """
    Links a Supabase user (identified by UUID) with a Django user.
    Stores Supabase-specific metadata.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Supabase User ID (from Supabase Auth)
    supabase_uid = models.UUIDField(
        unique=True,
        editable=False,
        help_text="Supabase user UID"
    )
    
    # Link to Django user
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='supabase_profile',
        help_text="Linked Django user"
    )
    
    # Tenant association
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='supabase_users',
        help_text="Tenant this user belongs to"
    )
    
    # User metadata from Supabase
    email = models.EmailField(
        validators=[EmailValidator()],
        help_text="User's email from Supabase"
    )
    
    # Role within the tenant
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('user', 'User'),
    ]
    
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='user',
        help_text="User's role in the tenant"
    )
    
    # Agent access permissions (set based on tenant subscription)
    # Default is False - user must be assigned to a tenant with subscription
    can_access_mark = models.BooleanField(
        default=False,
        help_text="Can access Mark's Agent"
    )
    can_access_hr = models.BooleanField(
        default=False,
        help_text="Can access HR Agent"
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this profile is active"
    )
    
    # Supabase metadata
    email_confirmed = models.BooleanField(
        default=False,
        help_text="Whether email is confirmed in Supabase"
    )
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="Phone number from Supabase"
    )
    avatar_url = models.URLField(
        blank=True,
        null=True,
        help_text="Avatar URL from Supabase"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last login timestamp"
    )
    
    # Metadata storage
    raw_metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Raw metadata from Supabase"
    )
    
    class Meta:
        db_table = 'supabase_users'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['supabase_uid']),
            models.Index(fields=['email']),
            models.Index(fields=['tenant']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.email} ({self.role}) - {self.tenant.name if self.tenant else 'No Tenant'}"
    
    def has_agent_access(self, agent_type):
        """
        Check if user has access to a specific agent.
        Requires BOTH user permission AND tenant subscription.
        
        Args:
            agent_type: 'mark' or 'hr'
        
        Returns:
            bool: True if access is allowed
        """
        if not self.is_active:
            return False
        
        if not self.tenant or not self.tenant.is_active:
            return False
        
        # Check tenant subscription first
        if agent_type == 'mark':
            # User must have permission AND tenant must have subscription
            return self.can_access_mark and self.tenant.has_mark_agent_access
        elif agent_type == 'hr':
            return self.can_access_hr and self.tenant.has_hr_agent_access
        
        return False
    
    def update_agent_permissions_from_tenant(self):
        """
        Update user's agent permissions based on tenant subscription.
        Called when user is assigned to a tenant or tenant subscription changes.
        """
        if not self.tenant:
            self.can_access_mark = False
            self.can_access_hr = False
            return
        
        # Set permissions based on tenant subscription
        # Only enable if tenant has the subscription
        if not self.tenant.has_mark_agent_access:
            self.can_access_mark = False
        
        if not self.tenant.has_hr_agent_access:
            self.can_access_hr = False
    
    def record_login(self):
        """Record a login event."""
        from django.utils import timezone
        self.last_login = timezone.now()
        self.save(update_fields=['last_login'])


class RefreshToken(models.Model):
    """
    Stores refresh tokens for Supabase sessions.
    Used for token rotation and session management.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    supabase_user = models.ForeignKey(
        SupabaseUser,
        on_delete=models.CASCADE,
        related_name='refresh_tokens',
        help_text="User this token belongs to"
    )
    
    token = models.TextField(
        help_text="The refresh token"
    )
    
    expires_at = models.DateTimeField(
        help_text="Token expiration time"
    )
    
    is_revoked = models.BooleanField(
        default=False,
        help_text="Whether this token has been revoked"
    )
    
    # Device/Session info
    device_info = models.JSONField(
        default=dict,
        blank=True,
        help_text="Device information"
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address when token was created"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'refresh_tokens'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Token for {self.supabase_user.email} ({'revoked' if self.is_revoked else 'active'})"
    
    def is_valid(self):
        """Check if token is still valid."""
        from django.utils import timezone
        return not self.is_revoked and self.expires_at > timezone.now()


class LoginAttempt(models.Model):
    """
    Track login attempts for security monitoring.
    """
    
    id = models.BigAutoField(primary_key=True)
    
    email = models.EmailField(
        help_text="Email attempted to login"
    )
    
    success = models.BooleanField(
        help_text="Whether the login was successful"
    )
    
    error_message = models.TextField(
        blank=True,
        null=True,
        help_text="Error message if failed"
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address of the attempt"
    )
    
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent of the attempt"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'login_attempts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['success']),
        ]
    
    def __str__(self):
        return f"Login attempt for {self.email} - {'Success' if self.success else 'Failed'}"


class Invitation(models.Model):
    """
    Invitations for users to join a tenant.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='invitations',
        help_text="Tenant to invite user to"
    )
    
    email = models.EmailField(
        help_text="Email address to invite"
    )
    
    invited_by = models.ForeignKey(
        SupabaseUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_invitations',
        help_text="User who sent the invitation"
    )
    
    role = models.CharField(
        max_length=20,
        choices=SupabaseUser.ROLE_CHOICES,
        default='user',
        help_text="Role to assign to invited user"
    )
    
    token = models.CharField(
        max_length=255,
        unique=True,
        help_text="Invitation token"
    )
    
    expires_at = models.DateTimeField(
        help_text="Invitation expiration time"
    )
    
    is_used = models.BooleanField(
        default=False,
        help_text="Whether this invitation has been used"
    )
    
    used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the invitation was used"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'invitations'
        ordering = ['-created_at']
        unique_together = ['tenant', 'email']
    
    def __str__(self):
        return f"Invitation to {self.tenant.name} for {self.email}"
    
    def is_valid(self):
        """Check if invitation is still valid."""
        from django.utils import timezone
        return not self.is_used and self.expires_at > timezone.now()
