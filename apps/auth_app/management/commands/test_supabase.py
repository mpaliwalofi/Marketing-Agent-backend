"""
Test Supabase connection and JWT verification.
Usage: python manage.py test_supabase
"""

import os
from django.core.management.base import BaseCommand
from apps.auth_app.supabase_client import supabase_auth


class Command(BaseCommand):
    help = "Test Supabase connection and JWT verification."

    def handle(self, *args, **options):
        self.stdout.write("Testing Supabase configuration...")

        url = os.getenv("SUPABASE_URL", "")
        anon_key = os.getenv("SUPABASE_ANON_KEY", "")
        jwt_secret = os.getenv("SUPABASE_JWT_SECRET", "")

        if not url:
            self.stdout.write(self.style.ERROR("SUPABASE_URL not set"))
            return
        if not anon_key:
            self.stdout.write(self.style.ERROR("SUPABASE_ANON_KEY not set"))
            return

        self.stdout.write(self.style.SUCCESS(f"SUPABASE_URL: {url}"))
        self.stdout.write(self.style.SUCCESS(f"SUPABASE_ANON_KEY: ...{anon_key[-8:]}"))

        if jwt_secret:
            self.stdout.write(self.style.SUCCESS("SUPABASE_JWT_SECRET: configured (fast local verification enabled)"))
        else:
            self.stdout.write(self.style.WARNING(
                "SUPABASE_JWT_SECRET not set — API-based JWT verification will be used (adds ~100ms per request). "
                "Add it from Supabase Dashboard > Settings > API > JWT Secret."
            ))

        token = input("\nPaste a Supabase JWT to test (leave empty to skip): ").strip()
        if token:
            is_valid, result = supabase_auth.verify_jwt(token)
            if is_valid:
                self.stdout.write(self.style.SUCCESS(
                    f"Token valid — uid={result.get('sub') or result.get('id')}, email={result.get('email')}"
                ))
            else:
                self.stdout.write(self.style.ERROR(f"Token invalid: {result.get('error')}"))
