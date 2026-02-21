"""
Tenant, agent configuration, API key, and request log models.

Tenant  — a company/organisation with a subscription to one or more agents.
AgentConfig  — per-tenant endpoint config for an external agent backend.
TenantAPIKey — API keys that allow a tenant's website to call the agent proxy.
AgentRequestLog — immutable audit trail of every agent proxy request.
"""

import uuid
import secrets
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils.crypto import get_random_string
from django.utils import timezone


class Tenant(models.Model):
    """
    A company or organisation that subscribes to SIA agents.
    Subscription type and status determine which agents the tenant's users can access.
    """

    SUBSCRIPTION_TYPE_CHOICES = [
        ("none", "No Subscription"),
        ("mark", "Mark's Agent"),
        ("hr", "HR Agent"),
        ("both", "Both Agents"),
    ]

    STATUS_CHOICES = [
        ("active", "Active"),
        ("trial", "Trial"),
        ("suspended", "Suspended"),
        ("cancelled", "Cancelled"),
    ]

    tenant_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Organisation info
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=100, unique=True)
    email = models.EmailField(help_text="Primary contact email")
    phone = models.CharField(max_length=20, blank=True, null=True)

    # Subscription
    subscription_type = models.CharField(
        max_length=10,
        choices=SUBSCRIPTION_TYPE_CHOICES,
        default="none",
    )
    subscription_status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="trial",
    )
    subscription_start = models.DateTimeField(null=True, blank=True)
    subscription_end = models.DateTimeField(
        null=True, blank=True, help_text="Null = no expiry"
    )

    # Usage limits
    rate_limit_per_minute = models.IntegerField(default=60)
    monthly_quota = models.IntegerField(default=1000)
    current_month_usage = models.IntegerField(default=0)

    # Internal notes (admin use only)
    notes = models.TextField(blank=True, null=True)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tenants"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["slug"]),
            models.Index(fields=["subscription_status"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.subscription_type})"

    def save(self, *args, **kwargs):
        if not self.slug:
            base = self.name.lower().replace(" ", "-")
            slug, n = base, 1
            while Tenant.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base}-{n}"
                n += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @property
    def is_subscription_active(self) -> bool:
        if self.subscription_status not in ("active", "trial"):
            return False
        if self.subscription_end and timezone.now() > self.subscription_end:
            return False
        return True

    @property
    def has_mark_agent_access(self) -> bool:
        return (
            self.is_active
            and self.is_subscription_active
            and self.subscription_type in ("mark", "both")
        )

    @property
    def has_hr_agent_access(self) -> bool:
        return (
            self.is_active
            and self.is_subscription_active
            and self.subscription_type in ("hr", "both")
        )

    def increment_usage(self):
        self.current_month_usage += 1
        self.save(update_fields=["current_month_usage"])

    def is_within_quota(self) -> bool:
        return self.current_month_usage < self.monthly_quota


class AgentConfig(models.Model):
    """
    External agent backend configuration for a tenant.
    One record per (tenant, agent_type) pair.
    """

    AGENT_TYPE_CHOICES = [
        ("mark", "Mark's Agent"),
        ("hr", "HR Agent"),
    ]

    tenant = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, related_name="agent_configs"
    )
    agent_type = models.CharField(max_length=10, choices=AGENT_TYPE_CHOICES)

    endpoint_url = models.URLField(max_length=500)
    api_key = models.CharField(max_length=500, null=True, blank=True)
    custom_headers = models.JSONField(default=dict, blank=True)
    timeout_seconds = models.IntegerField(default=30)
    max_retries = models.IntegerField(default=3)

    is_enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "agent_configs"
        unique_together = [("tenant", "agent_type")]
        ordering = ["tenant", "agent_type"]

    def __str__(self):
        return f"{self.tenant.name} — {self.get_agent_type_display()}"

    def get_auth_headers(self) -> dict:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.custom_headers)
        return headers


class TenantAPIKey(models.Model):
    """
    API keys for a tenant's website/app to call the agent proxy.
    Keys are stored hashed; only a short prefix is kept in plain text.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    tenant = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, related_name="api_keys"
    )
    name = models.CharField(max_length=100, help_text="E.g. 'Production Website'")

    # Hashed key storage
    key_hash = models.CharField(max_length=255)
    key_prefix = models.CharField(max_length=10, help_text="First 10 chars for identification")

    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    usage_count = models.IntegerField(default=0)
    last_used_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "tenant_api_keys"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["key_prefix"]),
            models.Index(fields=["tenant", "is_active"]),
        ]

    def __str__(self):
        return f"{self.tenant.name} — {self.name} ({self.key_prefix}…)"

    @classmethod
    def generate_key(cls):
        """Return (full_key, key_hash, key_prefix). full_key is shown once only."""
        full_key = f"sia_{get_random_string(32)}_{secrets.token_urlsafe(16)}"
        return full_key, make_password(full_key), full_key[:10]

    def verify_key(self, key: str) -> bool:
        return check_password(key, self.key_hash)

    def is_valid(self) -> bool:
        if not self.is_active:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    def record_usage(self):
        self.usage_count += 1
        self.last_used_at = timezone.now()
        self.save(update_fields=["usage_count", "last_used_at"])
        self.tenant.increment_usage()

    def revoke(self):
        self.is_active = False
        self.save(update_fields=["is_active"])


class AgentRequestLog(models.Model):
    """
    Immutable audit log for every agent proxy request.
    """

    STATUS_CHOICES = [
        ("success", "Success"),
        ("error", "Error"),
        ("timeout", "Timeout"),
        ("unauthorized", "Unauthorized"),
        ("rate_limited", "Rate Limited"),
    ]

    id = models.BigAutoField(primary_key=True)

    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="request_logs",
    )
    user = models.ForeignKey(
        "auth_app.UserProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="request_logs",
    )

    agent_type = models.CharField(
        max_length=10, choices=[("mark", "Mark"), ("hr", "HR")]
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    status_code = models.IntegerField(null=True, blank=True)
    response_time_ms = models.IntegerField()
    error_message = models.TextField(blank=True, null=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "agent_request_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant", "-created_at"]),
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["agent_type", "-created_at"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        who = self.user.email if self.user else (self.tenant.name if self.tenant else "anon")
        return f"{who} — {self.agent_type} — {self.status}"
