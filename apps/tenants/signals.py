"""
Signals for tenants app.
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.cache import cache
from .models import Tenant, TenantAPIKey, AgentConfig


@receiver(post_save, sender=TenantAPIKey)
def invalidate_api_key_cache(sender, instance, **kwargs):
    """Invalidate cache when API key is updated."""
    cache_key = f"tenant_api_key:{instance.key_prefix}"
    cache.delete(cache_key)


@receiver(post_delete, sender=TenantAPIKey)
def delete_api_key_cache(sender, instance, **kwargs):
    """Delete cache when API key is deleted."""
    cache_key = f"tenant_api_key:{instance.key_prefix}"
    cache.delete(cache_key)


@receiver(post_save, sender=AgentConfig)
def log_config_change(sender, instance, created, **kwargs):
    """Log when agent configuration changes."""
    from django.contrib.admin.models import LogEntry, CHANGE, ADDITION
    # This could be extended to send notifications
    pass
