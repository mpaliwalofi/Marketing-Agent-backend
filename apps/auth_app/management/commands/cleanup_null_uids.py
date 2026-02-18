"""
Clean up users with null supabase_uid.
Usage: python manage.py cleanup_null_uids
"""

from django.core.management.base import BaseCommand
from apps.auth_app.models import SupabaseUser


class Command(BaseCommand):
    help = 'Clean up SupabaseUsers with null supabase_uid'

    def handle(self, *args, **options):
        # Find users with null supabase_uid
        null_uid_users = SupabaseUser.objects.filter(supabase_uid__isnull=True)
        
        count = null_uid_users.count()
        
        if count == 0:
            self.stdout.write(self.style.SUCCESS("No users with null supabase_uid found."))
            return
        
        self.stdout.write(f"Found {count} users with null supabase_uid:")
        
        for user in null_uid_users:
            self.stdout.write(f"  - {user.email} (ID: {user.id})")
        
        self.stdout.write("\nThese users will be deleted. Their Django user accounts will also be removed.")
        self.stdout.write("Run with --delete flag to actually delete them.")
        
        if '--delete' in options.get('argv', []):
            for user in list(null_uid_users):
                self.stdout.write(f"Deleting {user.email}...")
                # The user.delete() will also delete the associated Django user via signal
                user.delete()
            
            self.stdout.write(self.style.SUCCESS(f"\nDeleted {count} users."))
