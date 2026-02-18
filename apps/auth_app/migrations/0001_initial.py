# Generated initial migration for auth_app

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('tenants', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='SupabaseUser',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('supabase_uid', models.UUIDField(editable=False, help_text='Supabase user UID', unique=True)),
                ('email', models.EmailField(help_text="User's email from Supabase", max_length=254)),
                ('role', models.CharField(choices=[('admin', 'Admin'), ('manager', 'Manager'), ('user', 'User')], default='user', help_text="User's role in the tenant", max_length=20)),
                ('can_access_mark', models.BooleanField(default=True, help_text="Can access Mark's Agent")),
                ('can_access_hr', models.BooleanField(default=True, help_text='Can access HR Agent')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this profile is active')),
                ('email_confirmed', models.BooleanField(default=False, help_text='Whether email is confirmed in Supabase')),
                ('phone', models.CharField(blank=True, help_text='Phone number from Supabase', max_length=20, null=True)),
                ('avatar_url', models.URLField(blank=True, help_text='Avatar URL from Supabase', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_login', models.DateTimeField(blank=True, help_text='Last login timestamp', null=True)),
                ('raw_metadata', models.JSONField(blank=True, default=dict, help_text='Raw metadata from Supabase')),
                ('tenant', models.ForeignKey(blank=True, help_text='Tenant this user belongs to', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='supabase_users', to='tenants.tenant')),
                ('user', models.OneToOneField(help_text='Linked Django user', on_delete=django.db.models.deletion.CASCADE, related_name='supabase_profile', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'supabase_users',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='RefreshToken',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('token', models.TextField(help_text='The refresh token')),
                ('expires_at', models.DateTimeField(help_text='Token expiration time')),
                ('is_revoked', models.BooleanField(default=False, help_text='Whether this token has been revoked')),
                ('device_info', models.JSONField(blank=True, default=dict, help_text='Device information')),
                ('ip_address', models.GenericIPAddressField(blank=True, help_text='IP address when token was created', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('supabase_user', models.ForeignKey(help_text='User this token belongs to', on_delete=django.db.models.deletion.CASCADE, related_name='refresh_tokens', to='auth_app.supabaseuser')),
            ],
            options={
                'db_table': 'refresh_tokens',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(help_text='Email attempted to login')),
                ('success', models.BooleanField(help_text='Whether the login was successful')),
                ('error_message', models.TextField(blank=True, help_text='Error message if failed', null=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, help_text='IP address of the attempt', null=True)),
                ('user_agent', models.TextField(blank=True, help_text='User agent of the attempt', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'login_attempts',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Invitation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(help_text='Email address to invite')),
                ('role', models.CharField(choices=[('admin', 'Admin'), ('manager', 'Manager'), ('user', 'User')], default='user', help_text='Role to assign to invited user', max_length=20)),
                ('token', models.CharField(help_text='Invitation token', max_length=255, unique=True)),
                ('expires_at', models.DateTimeField(help_text='Invitation expiration time')),
                ('is_used', models.BooleanField(default=False, help_text='Whether this invitation has been used')),
                ('used_at', models.DateTimeField(blank=True, help_text='When the invitation was used', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('invited_by', models.ForeignKey(blank=True, help_text='User who sent the invitation', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sent_invitations', to='auth_app.supabaseuser')),
                ('tenant', models.ForeignKey(help_text='Tenant to invite user to', on_delete=django.db.models.deletion.CASCADE, related_name='invitations', to='tenants.tenant')),
            ],
            options={
                'db_table': 'invitations',
                'ordering': ['-created_at'],
                'unique_together': {('tenant', 'email')},
            },
        ),
        migrations.AddIndex(
            model_name='supabaseuser',
            index=models.Index(fields=['supabase_uid'], name='supabase_us_supabas_6f0c0f_idx'),
        ),
        migrations.AddIndex(
            model_name='supabaseuser',
            index=models.Index(fields=['email'], name='supabase_us_email_6f5f5d_idx'),
        ),
        migrations.AddIndex(
            model_name='supabaseuser',
            index=models.Index(fields=['tenant'], name='supabase_us_tenant__4d5e10_idx'),
        ),
        migrations.AddIndex(
            model_name='supabaseuser',
            index=models.Index(fields=['is_active'], name='supabase_us_is_acti_7e6a12_idx'),
        ),
        migrations.AddIndex(
            model_name='loginattempt',
            index=models.Index(fields=['email', '-created_at'], name='loginattem_email_5a5f5d_idx'),
        ),
        migrations.AddIndex(
            model_name='loginattempt',
            index=models.Index(fields=['ip_address', '-created_at'], name='loginattem_ip_addr_8f6c12_idx'),
        ),
        migrations.AddIndex(
            model_name='loginattempt',
            index=models.Index(fields=['success'], name='loginattem_success_9a7b23_idx'),
        ),
    ]
