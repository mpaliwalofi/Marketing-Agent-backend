# Generated initial migration for tenants app

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Tenant',
            fields=[
                ('tenant_id', models.UUIDField(default=uuid.uuid4, editable=False, help_text='Unique tenant identifier (UUID)', primary_key=True, serialize=False)),
                ('name', models.CharField(help_text='Organization/Company name', max_length=255)),
                ('slug', models.SlugField(help_text='URL-friendly identifier for the tenant', max_length=100, unique=True)),
                ('email', models.EmailField(help_text='Primary contact email for the tenant', max_length=254)),
                ('phone', models.CharField(blank=True, help_text='Contact phone number', max_length=20, null=True)),
                ('subscribed_agents', models.CharField(choices=[('mark', "Mark's Agent"), ('hr', 'HR Agent'), ('both', 'Both Agents')], default='mark', help_text='Which agents the tenant has subscribed to', max_length=10)),
                ('status', models.CharField(choices=[('active', 'Active'), ('suspended', 'Suspended'), ('trial', 'Trial'), ('cancelled', 'Cancelled')], default='trial', help_text='Current tenant status', max_length=20)),
                ('subscription_start', models.DateTimeField(default=django.utils.timezone.now, help_text='When the subscription started')),
                ('subscription_end', models.DateTimeField(blank=True, help_text='When the subscription expires (null = no expiry)', null=True)),
                ('rate_limit_per_minute', models.IntegerField(default=60, help_text='API rate limit per minute for this tenant')),
                ('monthly_quota', models.IntegerField(default=1000, help_text='Monthly API call quota')),
                ('current_month_usage', models.IntegerField(default=0, help_text="Current month's API usage")),
                ('billing_email', models.EmailField(blank=True, help_text='Email for billing notifications', max_length=254, null=True)),
                ('stripe_customer_id', models.CharField(blank=True, help_text='Stripe customer ID for billing', max_length=255, null=True)),
                ('allowed_domains', models.JSONField(blank=True, default=list, help_text="List of allowed domains for CORS (e.g., ['example.com', 'app.example.com'])")),
                ('ip_whitelist', models.JSONField(blank=True, default=list, help_text='List of allowed IP addresses (empty = allow all)')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_activity', models.DateTimeField(blank=True, help_text='Last API activity timestamp', null=True)),
                ('notes', models.TextField(blank=True, help_text='Internal notes about the tenant', null=True)),
            ],
            options={
                'db_table': 'tenants',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='TenantUser',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(help_text="User's email address", max_length=254)),
                ('name', models.CharField(help_text="User's full name", max_length=255)),
                ('role', models.CharField(choices=[('admin', 'Admin'), ('user', 'User'), ('viewer', 'Viewer')], default='user', help_text="User's role in the tenant", max_length=20)),
                ('can_access_mark', models.BooleanField(default=True, help_text="Can access Mark's Agent")),
                ('can_access_hr', models.BooleanField(default=True, help_text='Can access HR Agent')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this user account is active')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_login', models.DateTimeField(blank=True, help_text='Last login timestamp', null=True)),
                ('tenant', models.ForeignKey(help_text='Tenant this user belongs to', on_delete=django.db.models.deletion.CASCADE, related_name='users', to='tenants.tenant')),
            ],
            options={
                'db_table': 'tenant_users',
                'ordering': ['-created_at'],
                'unique_together': {('tenant', 'email')},
            },
        ),
        migrations.CreateModel(
            name='TenantAPIKey',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(help_text="Descriptive name for this key (e.g., 'Production Web App')", max_length=100)),
                ('key_type', models.CharField(choices=[('production', 'Production'), ('sandbox', 'Sandbox'), ('webhook', 'Webhook')], default='production', help_text='Type of API key', max_length=20)),
                ('key_hash', models.CharField(help_text='Hashed API key for verification', max_length=255)),
                ('key_prefix', models.CharField(help_text='First 8 characters of the key for identification', max_length=8)),
                ('allowed_ips', models.JSONField(blank=True, default=list, help_text='IP addresses allowed to use this key')),
                ('usage_count', models.IntegerField(default=0, help_text='Number of times this key has been used')),
                ('last_used_at', models.DateTimeField(blank=True, help_text='Last usage timestamp', null=True)),
                ('expires_at', models.DateTimeField(blank=True, help_text='Key expiration date (null = never expires)', null=True)),
                ('is_active', models.BooleanField(default=True, help_text='Whether this key is currently active')),
                ('revoked_at', models.DateTimeField(blank=True, help_text='When the key was revoked', null=True)),
                ('revoked_reason', models.TextField(blank=True, help_text='Reason for revocation', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.CharField(blank=True, help_text='User who created this key', max_length=255, null=True)),
                ('tenant', models.ForeignKey(help_text='Tenant this key belongs to', on_delete=django.db.models.deletion.CASCADE, related_name='api_keys', to='tenants.tenant')),
            ],
            options={
                'db_table': 'tenant_api_keys',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='AgentRequestLog',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('agent_type', models.CharField(choices=[('mark', 'Mark'), ('hr', 'HR')], help_text='Agent type requested', max_length=10)),
                ('request_id', models.UUIDField(default=uuid.uuid4, help_text='Unique request identifier')),
                ('request_method', models.CharField(help_text='HTTP method used', max_length=10)),
                ('request_path', models.CharField(help_text='Request path', max_length=500)),
                ('request_headers', models.JSONField(blank=True, default=dict, help_text='Request headers (sanitized)')),
                ('request_body', models.JSONField(blank=True, help_text='Request body', null=True)),
                ('status', models.CharField(choices=[('success', 'Success'), ('error', 'Error'), ('timeout', 'Timeout'), ('unauthorized', 'Unauthorized'), ('rate_limited', 'Rate Limited')], help_text='Request status', max_length=20)),
                ('status_code', models.IntegerField(blank=True, help_text='HTTP status code', null=True)),
                ('response_body', models.JSONField(blank=True, help_text='Response body (truncated)', null=True)),
                ('error_message', models.TextField(blank=True, help_text='Error message if failed', null=True)),
                ('response_time_ms', models.IntegerField(help_text='Response time in milliseconds')),
                ('client_ip', models.GenericIPAddressField(blank=True, help_text='Client IP address', null=True)),
                ('user_agent', models.TextField(blank=True, help_text='Client user agent', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('tenant', models.ForeignKey(help_text='Tenant making the request', on_delete=django.db.models.deletion.CASCADE, related_name='request_logs', to='tenants.tenant')),
            ],
            options={
                'db_table': 'agent_request_logs',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='AgentConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('agent_type', models.CharField(choices=[('mark', "Mark's Agent"), ('hr', 'HR Agent')], help_text='Type of agent', max_length=10)),
                ('endpoint_url', models.URLField(help_text='External agent API endpoint URL', max_length=500)),
                ('api_key', models.CharField(blank=True, help_text='API key for the external agent (encrypted)', max_length=255, null=True)),
                ('api_secret', models.CharField(blank=True, help_text='API secret/password for the external agent (encrypted)', max_length=255, null=True)),
                ('custom_headers', models.JSONField(blank=True, default=dict, help_text="Custom headers to send with requests (e.g., {'X-Custom-Header': 'value'})")),
                ('timeout_seconds', models.IntegerField(default=30, help_text='Request timeout in seconds')),
                ('max_retries', models.IntegerField(default=3, help_text='Maximum number of retries on failure')),
                ('webhook_url', models.URLField(blank=True, help_text='Webhook URL for receiving async responses', max_length=500, null=True)),
                ('is_enabled', models.BooleanField(default=True, help_text='Whether this agent configuration is active')),
                ('last_health_check', models.DateTimeField(blank=True, help_text='Last successful health check timestamp', null=True)),
                ('health_status', models.CharField(choices=[('healthy', 'Healthy'), ('unhealthy', 'Unhealthy'), ('unknown', 'Unknown')], default='unknown', help_text='Current health status of the agent', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tenant', models.ForeignKey(help_text='Tenant this configuration belongs to', on_delete=django.db.models.deletion.CASCADE, related_name='agent_configs', to='tenants.tenant')),
            ],
            options={
                'db_table': 'agent_configs',
                'ordering': ['tenant', 'agent_type'],
                'unique_together': {('tenant', 'agent_type')},
            },
        ),
        migrations.AddIndex(
            model_name='tenant',
            index=models.Index(fields=['slug'], name='tenants_slug_5a0f92_idx'),
        ),
        migrations.AddIndex(
            model_name='tenant',
            index=models.Index(fields=['status'], name='tenants_status_8a5f1c_idx'),
        ),
        migrations.AddIndex(
            model_name='tenant',
            index=models.Index(fields=['subscribed_agents'], name='tenants_subscri_7c5e3a_idx'),
        ),
        migrations.AddIndex(
            model_name='tenant',
            index=models.Index(fields=['email'], name='tenants_email_6c6a0c_idx'),
        ),
        migrations.AddIndex(
            model_name='tenantapikey',
            index=models.Index(fields=['key_prefix'], name='tenantapike_key_pr_8ed5b5_idx'),
        ),
        migrations.AddIndex(
            model_name='tenantapikey',
            index=models.Index(fields=['is_active'], name='tenantapike_is_acti_b55bda_idx'),
        ),
        migrations.AddIndex(
            model_name='tenantapikey',
            index=models.Index(fields=['tenant', 'is_active'], name='tenantapike_tenant__d10a39_idx'),
        ),
        migrations.AddIndex(
            model_name='agentrequestlog',
            index=models.Index(fields=['tenant', '-created_at'], name='agentrequ_tenant__88bb00_idx'),
        ),
        migrations.AddIndex(
            model_name='agentrequestlog',
            index=models.Index(fields=['agent_type', '-created_at'], name='agentrequ_agent_t_9b381c_idx'),
        ),
        migrations.AddIndex(
            model_name='agentrequestlog',
            index=models.Index(fields=['status'], name='agentrequ_status_26e84f_idx'),
        ),
        migrations.AddIndex(
            model_name='agentrequestlog',
            index=models.Index(fields=['request_id'], name='agentrequ_request_3c7c71_idx'),
        ),
        migrations.AddIndex(
            model_name='agentrequestlog',
            index=models.Index(fields=['created_at'], name='agentrequ_created_53f5d7_idx'),
        ),
    ]
