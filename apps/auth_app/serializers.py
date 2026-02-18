"""
Serializers for authentication.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import SupabaseUser, Invitation


class RegisterSerializer(serializers.Serializer):
    """Serializer for user registration."""
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, min_length=8, write_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    tenant_id = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    
    def validate_tenant_id(self, value):
        """Validate tenant_id is a valid UUID or empty."""
        if not value or value == '' or value == 'null':
            return None
        try:
            import uuid
            return uuid.UUID(str(value))
        except (ValueError, TypeError):
            raise serializers.ValidationError('Must be a valid UUID.')
    
    def validate_email(self, value):
        """Validate email is not already in use."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already registered')
        return value
    
    def validate_password(self, value):
        """Validate password strength."""
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters')
        return value


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class TokenRefreshSerializer(serializers.Serializer):
    """Serializer for token refresh."""
    
    refresh_token = serializers.CharField(required=True)


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile."""
    
    username = serializers.CharField(source='user.username', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    date_joined = serializers.DateTimeField(source='user.date_joined', read_only=True)
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    
    class Meta:
        model = SupabaseUser
        fields = [
            'id', 'supabase_uid', 'username', 'email', 'first_name', 'last_name',
            'role', 'tenant', 'tenant_name', 'can_access_mark', 'can_access_hr',
            'email_confirmed', 'phone', 'avatar_url', 'is_active',
            'date_joined', 'last_login', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'supabase_uid', 'tenant', 'email_confirmed',
            'created_at', 'updated_at', 'last_login'
        ]


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile."""
    
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    
    class Meta:
        model = SupabaseUser
        fields = [
            'first_name', 'last_name', 'phone', 'avatar_url'
        ]
    
    def update(self, instance, validated_data):
        # Update Django user fields
        user_data = validated_data.pop('user', {})
        if user_data:
            if 'first_name' in user_data:
                instance.user.first_name = user_data['first_name']
            if 'last_name' in user_data:
                instance.user.last_name = user_data['last_name']
            instance.user.save()
        
        # Update SupabaseUser fields
        return super().update(instance, validated_data)


class InvitationSerializer(serializers.ModelSerializer):
    """Serializer for invitations."""
    
    invited_by_name = serializers.CharField(source='invited_by.email', read_only=True)
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    
    class Meta:
        model = Invitation
        fields = [
            'id', 'email', 'tenant', 'tenant_name', 'role', 'invited_by_name',
            'token', 'expires_at', 'is_used', 'used_at', 'created_at'
        ]
        read_only_fields = [
            'id', 'token', 'is_used', 'used_at', 'created_at', 'invited_by_name'
        ]


class AcceptInvitationSerializer(serializers.Serializer):
    """Serializer for accepting an invitation."""
    
    token = serializers.CharField(required=True)


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""
    
    email = serializers.EmailField(required=True)


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, min_length=8, write_only=True)
    
    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters')
        return value


class UserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users in a tenant."""
    
    username = serializers.CharField(source='user.username', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    
    class Meta:
        model = SupabaseUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'can_access_mark', 'can_access_hr', 'is_active', 'last_login'
        ]


class UserRoleUpdateSerializer(serializers.Serializer):
    """Serializer for updating user role."""
    
    role = serializers.ChoiceField(choices=['admin', 'manager', 'user'])
    can_access_mark = serializers.BooleanField(required=False)
    can_access_hr = serializers.BooleanField(required=False)
