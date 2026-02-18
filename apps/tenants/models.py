"""
Multi-tenant models for SaaS architecture.
Supports Mark's Agent (n8n) and HR Agent (AWS) access control.
"""

from django.db import models
from django.core.validators import EmailValidator, RegexValidator
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.utils.crypto import get_random_string
import uuid
import secrets


class Tenant(models.Model):
    """
    Represents a tenant/customer in the multi-tenant system.
    Each tenant can have access to one or multiple agents based on subscription.
    """
    
    AGENT_CHOICES = [
        ('mark', 'Mark\'s Agent'),
        ('hr', 'HR Agent'),
        ('both', 'Both Agents'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('trial', 'Trial'),
        ('cancelled', 'Cancelled'),
    ]
    
    # Primary Identification
    tenant_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique tenant identifier (UUID)"
    )
    
    # Organization Information
    name = models.CharField(
        max_length=255,
        help_text="Organization/Company name"
    )
    slug = models.SlugField(
        max_length=100,
        unique=True,
        help_text="URL-friendly identifier for the tenant"
    )
    
    # Contact Information
    email = models.EmailField(
        validators=[EmailValidator()],
        help_text="Primary contact email for the tenant"
    )
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="Contact phone number"
    )
    
    # Subscription & Access Control
    subscribed_agents = models.CharField(
        max_length=10,
        choices=AGENT_CHOICES,
        default='mark',
        help_text="Which agents the tenant has subscribed to"
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='trial',
        help_text="Current tenant status"
    )
    
    # Subscription Dates
    subscription_start = models.DateTimeField(
        default=timezone.now,
        help_text="When the subscription started"
    )
    subscription_end = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the subscription expires (null = no expiry)"
    )
    
    # Rate Limiting & Quotas
    rate_limit_per_minute = models.IntegerField(
        default=60,
        help_text="API rate limit per minute for this tenant"
    )
    monthly_quota = models.IntegerField(
        default=1000,
        help_text="Monthly API call quota"
    )
    current_month_usage = models.IntegerField(
        default=0,
        help_text="Current month's API usage"
    )
    
    # Billing Information
    billing_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Email for billing notifications"
    )
    stripe_customer_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Stripe customer ID for billing"
    )
    
    # Security
    allowed_domains = models.JSONField(
        default=list,
        blank=True,
        help_text="List of allowed domains for CORS (e.g., ['example.com', 'app.example.com'])"
    )
    ip_whitelist = models.JSONField(
        default=list,
        blank=True,
        help_text="List of allowed IP addresses (empty = allow all)"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_activity = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last API activity timestamp"
    )
    
    # Notes
    notes = models.TextField(
        blank=True,
        null=True,
        help_text="Internal notes about the tenant"
    )
    
    class Meta:
        db_table = 'tenants'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['status']),
            models.Index(fields=['subscribed_agents']),
            models.Index(fields=['email']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.tenant_id})"
    
    def save(self, *args, **kwargs):
        # Auto-generate slug if not provided
        if not self.slug:
            base_slug = self.name.lower().replace(' ', '-')
            slug = base_slug
            counter = 1
            while Tenant.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)
    
    @property
    def is_active(self):
        """Check if tenant subscription is active and not expired."""
        if self.status not in ['active', 'trial']:
            return False
        if self.subscription_end and timezone.now() > self.subscription_end:
            return False
        return True
    
    @property
    def has_mark_agent_access(self):
        """Check if tenant has access to Mark's Agent."""
        return self.is_active and self.subscribed_agents in ['mark', 'both']
    
    @property
    def has_hr_agent_access(self):
        """Check if tenant has access to HR Agent."""
        return self.is_active and self.subscribed_agents in ['hr', 'both']
    
    def can_access_agent(self, agent_type):
        """
        Check if tenant can access a specific agent type.
        
        Args:
            agent_type: 'mark' or 'hr'
        
        Returns:
            bool: True if access is allowed
        """
        if agent_type == 'mark':
            return self.has_mark_agent_access
        elif agent_type == 'hr':
            return self.has_hr_agent_access
        return False
    
    def increment_usage(self):
        """Increment the monthly API usage counter."""
        self.current_month_usage += 1
        self.last_activity = timezone.now()
        self.save(update_fields=['current_month_usage', 'last_activity'])
    
    def reset_monthly_usage(self):
        """Reset monthly usage counter (call at start of month)."""
        self.current_month_usage = 0
        self.save(update_fields=['current_month_usage'])
    
    def is_within_quota(self):
        """Check if tenant is within their monthly quota."""
        return self.current_month_usage < self.monthly_quota


class AgentConfig(models.Model):
    """
    Configuration for external agent backends.
    Stores API endpoints and credentials for Mark's Agent (n8n) and HR Agent (AWS).
    """
    
    AGENT_TYPE_CHOICES = [
        ('mark', 'Mark\'s Agent'),
        ('hr', 'HR Agent'),
    ]
    
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='agent_configs',
        help_text="Tenant this configuration belongs to"
    )
    
    agent_type = models.CharField(
        max_length=10,
        choices=AGENT_TYPE_CHOICES,
        help_text="Type of agent"
    )
    
    # External Agent Configuration
    endpoint_url = models.URLField(
        max_length=500,
        help_text="External agent API endpoint URL"
    )
    
    # Authentication (stored encrypted)
    api_key = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="API key for the external agent (encrypted)"
    )
    
    api_secret = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="API secret/password for the external agent (encrypted)"
    )
    
    # Additional Headers (for custom authentication)
    custom_headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Custom headers to send with requests (e.g., {'X-Custom-Header': 'value'})"
    )
    
    # Request Configuration
    timeout_seconds = models.IntegerField(
        default=30,
        help_text="Request timeout in seconds"
    )
    max_retries = models.IntegerField(
        default=3,
        help_text="Maximum number of retries on failure"
    )
    
    # Webhook Configuration (for async responses)
    webhook_url = models.URLField(
        max_length=500,
        blank=True,
        null=True,
        help_text="Webhook URL for receiving async responses"
    )
    
    # Status
    is_enabled = models.BooleanField(
        default=True,
        help_text="Whether this agent configuration is active"
    )
    last_health_check = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last successful health check timestamp"
    )
    health_status = models.CharField(
        max_length=20,
        default='unknown',
        choices=[
            ('healthy', 'Healthy'),
            ('unhealthy', 'Unhealthy'),
            ('unknown', 'Unknown'),
        ],
        help_text="Current health status of the agent"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'agent_configs'
        unique_together = ['tenant', 'agent_type']
        ordering = ['tenant', 'agent_type']
    
    def __str__(self):
        return f"{self.tenant.name} - {self.get_agent_type_display()}"
    
    def get_auth_headers(self):
        """
        Build authentication headers for the external agent.
        
        Returns:
            dict: Headers to include in requests
        """
        headers = {}
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        if self.api_secret:
            headers['X-API-Secret'] = self.api_secret
        
        # Add custom headers
        headers.update(self.custom_headers)
        
        return headers


class TenantAPIKey(models.Model):
    """
    API keys for tenant authentication.
    Supports multiple keys per tenant for rotation and different use cases.
    """
    
    KEY_TYPE_CHOICES = [
        ('production', 'Production'),
        ('sandbox', 'Sandbox'),
        ('webhook', 'Webhook'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='api_keys',
        help_text="Tenant this key belongs to"
    )
    
    # Key Information
    name = models.CharField(
        max_length=100,
        help_text="Descriptive name for this key (e.g., 'Production Web App')"
    )
    key_type = models.CharField(
        max_length=20,
        choices=KEY_TYPE_CHOICES,
        default='production',
        help_text="Type of API key"
    )
    
    # The actual key (hashed for storage, only shown once on creation)
    key_hash = models.CharField(
        max_length=255,
        help_text="Hashed API key for verification"
    )
    key_prefix = models.CharField(
        max_length=8,
        help_text="First 8 characters of the key for identification"
    )
    
    # Restrictions
    allowed_ips = models.JSONField(
        default=list,
        blank=True,
        help_text="IP addresses allowed to use this key"
    )
    
    # Usage Tracking
    usage_count = models.IntegerField(
        default=0,
        help_text="Number of times this key has been used"
    )
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last usage timestamp"
    )
    
    # Expiration
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Key expiration date (null = never expires)"
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this key is currently active"
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the key was revoked"
    )
    revoked_reason = models.TextField(
        blank=True,
        null=True,
        help_text="Reason for revocation"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="User who created this key"
    )
    
    class Meta:
        db_table = 'tenant_api_keys'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['key_prefix']),
            models.Index(fields=['is_active']),
            models.Index(fields=['tenant', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.tenant.name} - {self.name} ({self.key_prefix}...)"
    
    @classmethod
    def generate_key(cls):
        """
        Generate a new secure API key.
        
        Returns:
            tuple: (full_key, key_hash, key_prefix)
        """
        # Generate a secure random key
        full_key = f"sia_{get_random_string(32)}_{secrets.token_urlsafe(16)}"
        key_hash = make_password(full_key)
        key_prefix = full_key[:8]
        return full_key, key_hash, key_prefix
    
    def verify_key(self, key):
        """
        Verify if the provided key matches.
        
        Args:
            key: The API key to verify
        
        Returns:
            bool: True if valid
        """
        return check_password(key, self.key_hash)
    
    def is_valid(self):
        """
        Check if the key is valid (active and not expired).
        
        Returns:
            bool: True if valid
        """
        if not self.is_active:
            return False
        if self.revoked_at:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True
    
    def record_usage(self):
        """Record that this key was used."""
        self.usage_count += 1
        self.last_used_at = timezone.now()
        self.save(update_fields=['usage_count', 'last_used_at'])
        # Also update tenant activity
        self.tenant.increment_usage()
    
    def revoke(self, reason=None):
        """Revoke this API key."""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revoked_reason = reason
        self.save(update_fields=['is_active', 'revoked_at', 'revoked_reason'])


class AgentRequestLog(models.Model):
    """
    Log of all agent requests for auditing and debugging.
    """
    
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('error', 'Error'),
        ('timeout', 'Timeout'),
        ('unauthorized', 'Unauthorized'),
        ('rate_limited', 'Rate Limited'),
    ]
    
    id = models.BigAutoField(primary_key=True)
    
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='request_logs',
        help_text="Tenant making the request"
    )
    
    agent_type = models.CharField(
        max_length=10,
        choices=[('mark', 'Mark'), ('hr', 'HR')],
        help_text="Agent type requested"
    )
    
    # Request Details
    request_id = models.UUIDField(
        default=uuid.uuid4,
        help_text="Unique request identifier"
    )
    request_method = models.CharField(
        max_length=10,
        help_text="HTTP method used"
    )
    request_path = models.CharField(
        max_length=500,
        help_text="Request path"
    )
    request_headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Request headers (sanitized)"
    )
    request_body = models.JSONField(
        null=True,
        blank=True,
        help_text="Request body"
    )
    
    # Response Details
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        help_text="Request status"
    )
    status_code = models.IntegerField(
        null=True,
        blank=True,
        help_text="HTTP status code"
    )
    response_body = models.JSONField(
        null=True,
        blank=True,
        help_text="Response body (truncated)"
    )
    error_message = models.TextField(
        blank=True,
        null=True,
        help_text="Error message if failed"
    )
    
    # Performance Metrics
    response_time_ms = models.IntegerField(
        help_text="Response time in milliseconds"
    )
    
    # Client Information
    client_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Client IP address"
    )
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="Client user agent"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'agent_request_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', '-created_at']),
            models.Index(fields=['agent_type', '-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['request_id']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.tenant.name} - {self.agent_type} - {self.status} ({self.created_at})"


class TenantUser(models.Model):
    """
    Users belonging to a tenant organization.
    For tracking who within a tenant is making requests.
    """
    
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'User'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='users',
        help_text="Tenant this user belongs to"
    )
    
    # User Information
    email = models.EmailField(
        validators=[EmailValidator()],
        help_text="User's email address"
    )
    name = models.CharField(
        max_length=255,
        help_text="User's full name"
    )
    
    # Role & Permissions
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='user',
        help_text="User's role in the tenant"
    )
    
    # Access Control
    can_access_mark = models.BooleanField(
        default=True,
        help_text="Can access Mark's Agent"
    )
    can_access_hr = models.BooleanField(
        default=True,
        help_text="Can access HR Agent"
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this user account is active"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last login timestamp"
    )
    
    class Meta:
        db_table = 'tenant_users'
        unique_together = ['tenant', 'email']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.email}) - {self.tenant.name}"
