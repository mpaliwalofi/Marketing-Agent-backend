"""
Management command to set up a new tenant with agents.
Usage: python manage.py setup_tenant --name "Acme Corp" --email "admin@acme.com" --agents both
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from apps.tenants.models import Tenant, AgentConfig, TenantAPIKey
from apps.tenants.services import TenantService


class Command(BaseCommand):
    help = 'Set up a new tenant with agent configurations and API key'

    def add_arguments(self, parser):
        parser.add_argument('--name', required=True, help='Tenant/company name')
        parser.add_argument('--email', required=True, help='Admin email address')
        parser.add_argument('--agents', choices=['mark', 'hr', 'both'], default='mark',
                          help='Which agents to subscribe to')
        parser.add_argument('--mark-url', help='Mark\'s Agent endpoint URL')
        parser.add_argument('--hr-url', help='HR Agent endpoint URL')
        parser.add_argument('--quota', type=int, default=1000, help='Monthly API quota')
        parser.add_argument('--no-key', action='store_true', help='Skip API key generation')

    def handle(self, *args, **options):
        name = options['name']
        email = options['email']
        agents = options['agents']
        mark_url = options['mark_url']
        hr_url = options['hr_url']
        quota = options['quota']
        no_key = options['no_key']

        try:
            with transaction.atomic():
                # Create tenant
                self.stdout.write(f"Creating tenant: {name}")
                tenant = Tenant.objects.create(
                    name=name,
                    email=email,
                    subscribed_agents=agents,
                    monthly_quota=quota,
                    status='active'
                )
                self.stdout.write(self.style.SUCCESS(f"  ✓ Tenant created: {tenant.tenant_id}"))
                self.stdout.write(f"  ✓ Slug: {tenant.slug}")

                # Configure Mark's Agent if needed
                if agents in ['mark', 'both'] and mark_url:
                    AgentConfig.objects.create(
                        tenant=tenant,
                        agent_type='mark',
                        endpoint_url=mark_url,
                        is_enabled=True
                    )
                    self.stdout.write(self.style.SUCCESS(f"  ✓ Mark's Agent configured: {mark_url}"))
                elif agents in ['mark', 'both']:
                    self.stdout.write(self.style.WARNING(
                        f"  ⚠ Mark's Agent not configured - no endpoint URL provided"
                    ))

                # Configure HR Agent if needed
                if agents in ['hr', 'both'] and hr_url:
                    AgentConfig.objects.create(
                        tenant=tenant,
                        agent_type='hr',
                        endpoint_url=hr_url,
                        is_enabled=True
                    )
                    self.stdout.write(self.style.SUCCESS(f"  ✓ HR Agent configured: {hr_url}"))
                elif agents in ['hr', 'both']:
                    self.stdout.write(self.style.WARNING(
                        f"  ⚠ HR Agent not configured - no endpoint URL provided"
                    ))

                # Generate API key
                if not no_key:
                    full_key, key_obj = TenantService.create_api_key(
                        tenant=tenant,
                        name='Default Production Key',
                        key_type='production'
                    )
                    self.stdout.write(self.style.SUCCESS(f"  ✓ API Key created: {key_obj.key_prefix}..."))
                    self.stdout.write("")
                    self.stdout.write(self.style.WARNING("=" * 60))
                    self.stdout.write(self.style.WARNING("IMPORTANT: SAVE THIS API KEY!"))
                    self.stdout.write(self.style.WARNING("=" * 60))
                    self.stdout.write("")
                    self.stdout.write(self.style.NOTICE(f"  {full_key}"))
                    self.stdout.write("")
                    self.stdout.write(self.style.WARNING("=" * 60))
                    self.stdout.write(self.style.WARNING("This key will NOT be shown again!"))
                    self.stdout.write(self.style.WARNING("=" * 60))

                self.stdout.write("")
                self.stdout.write(self.style.SUCCESS("=" * 60))
                self.stdout.write(self.style.SUCCESS("Tenant setup complete!"))
                self.style.SUCCESS("=" * 60)
                self.stdout.write(f"Tenant ID: {tenant.tenant_id}")
                self.stdout.write(f"Slug: {tenant.slug}")
                self.stdout.write(f"Subscription: {agents}")
                self.stdout.write(f"Monthly Quota: {quota}")

        except Exception as e:
            raise CommandError(f"Failed to create tenant: {e}")
