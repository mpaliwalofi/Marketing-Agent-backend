"""
User profile model — single source of truth for all user data.

Supabase Auth handles JWT tokens, sessions, email verification, and password reset.
This model stores app-specific user data linked via supabase_uid.

Replaces the old: auth.User (business use) + SupabaseUser + TenantUser
"""

import uuid
from django.db import models
from django.core.validators import EmailValidator
from django.utils import timezone


class UserProfile(models.Model):
    """
    Single user table linking Supabase Auth UID to user profile and subscription.

    Access to agents is determined by the user's Tenant subscription:
      tenant.subscription_type in ['mark', 'both']  → can access Mark's Agent
      tenant.subscription_type in ['hr', 'both']    → can access HR Agent
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to Supabase Auth
    supabase_uid = models.UUIDField(
        unique=True,
        editable=False,
        help_text="Supabase Auth user ID",
    )

    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
    )
    full_name = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    avatar_url = models.URLField(null=True, blank=True)

    # Platform role — 'super_admin' is the platform administrator
    ROLE_CHOICES = [
        ("super_admin", "Super Admin"),
        ("user", "User"),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="user")

    # Tenant association — set by admin
    tenant = models.ForeignKey(
        "tenants.Tenant",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="members",
        help_text="Company/org this user belongs to",
    )

    is_active = models.BooleanField(default=True)
    email_confirmed = models.BooleanField(default=False)

    last_login = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # ------------------------------------------------------------------ #
    # DRF / Django compatibility — makes UserProfile work as request.user #
    # ------------------------------------------------------------------ #
    is_authenticated = True
    is_anonymous = False

    class Meta:
        db_table = "user_profiles"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["supabase_uid"]),
            models.Index(fields=["email"]),
            models.Index(fields=["role"]),
            models.Index(fields=["tenant"]),
        ]

    def __str__(self):
        return f"{self.email} ({self.role})"

    # ------------------------------------------------------------------ #
    # Agent access helpers                                                  #
    # ------------------------------------------------------------------ #

    @property
    def can_access_mark(self) -> bool:
        return (
            self.is_active
            and self.tenant is not None
            and self.tenant.has_mark_agent_access
        )

    @property
    def can_access_hr(self) -> bool:
        return (
            self.is_active
            and self.tenant is not None
            and self.tenant.has_hr_agent_access
        )

    @property
    def is_super_admin(self) -> bool:
        return self.role == "super_admin"

    def get_accessible_agents(self) -> list:
        agents = []
        if self.can_access_mark:
            agents.append("mark")
        if self.can_access_hr:
            agents.append("hr")
        return agents

    def record_login(self):
        self.last_login = timezone.now()
        self.save(update_fields=["last_login"])
