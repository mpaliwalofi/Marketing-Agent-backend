"""
Signals for auth app.
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import SupabaseUser


@receiver(post_delete, sender=SupabaseUser)
def cleanup_django_user(sender, instance, **kwargs):
    """Delete the associated Django user when SupabaseUser is deleted."""
    if instance.user:
        instance.user.delete()


@receiver(post_save, sender=User)
def create_supabase_profile(sender, instance, created, **kwargs):
    """
    Note: This is a placeholder. 
    In production, SupabaseUser should be created during registration flow.
    """
    pass
