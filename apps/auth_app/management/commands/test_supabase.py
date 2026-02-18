"""
Test Supabase connection and token verification.
Usage: python manage.py test_supabase
"""

from django.core.management.base import BaseCommand
from apps.auth_app.supabase_client import supabase_auth, SupabaseConfig


class Command(BaseCommand):
    help = 'Test Supabase connection'

    def handle(self, *args, **options):
        self.stdout.write("Testing Supabase Configuration...")
        
        # Check configuration
        if not SupabaseConfig.SUPABASE_URL:
            self.stdout.write(self.style.ERROR("❌ SUPABASE_URL not set"))
            return
        
        if not SupabaseConfig.SUPABASE_ANON_KEY:
            self.stdout.write(self.style.ERROR("❌ SUPABASE_ANON_KEY not set"))
            return
        
        self.stdout.write(self.style.SUCCESS(f"✅ SUPABASE_URL: {SupabaseConfig.SUPABASE_URL}"))
        self.stdout.write(self.style.SUCCESS(f"✅ SUPABASE_ANON_KEY: {'*' * 10}{SupabaseConfig.SUPABASE_ANON_KEY[-10:]}"))
        
        if SupabaseConfig.SUPABASE_JWT_SECRET:
            self.stdout.write(self.style.SUCCESS(f"✅ SUPABASE_JWT_SECRET: {'*' * 10} (configured)"))
        else:
            self.stdout.write(self.style.WARNING("⚠️ SUPABASE_JWT_SECRET not set - will use API verification"))
        
        # Test token prompt
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Enter a Supabase JWT token to test verification:")
        self.stdout.write("(Leave empty to skip)")
        
        import sys
        token = input("> ").strip()
        
        if token:
            self.stdout.write("\nVerifying token...")
            is_valid, result = supabase_auth.verify_jwt(token)
            
            if is_valid:
                self.stdout.write(self.style.SUCCESS("✅ Token is valid!"))
                self.stdout.write(f"\nUser ID: {result.get('sub')}")
                self.stdout.write(f"Email: {result.get('email')}")
                self.stdout.write(f"Role: {result.get('role')}")
            else:
                self.stdout.write(self.style.ERROR(f"❌ Token invalid: {result.get('error')}"))
                if 'details' in result:
                    self.stdout.write(f"Details: {result.get('details')}")
