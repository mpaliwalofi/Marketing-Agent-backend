"""
URL configuration for auth app.
"""

from django.urls import path
from . import views
from . import views_debug

urlpatterns = [
    # Authentication
    path('register/', views.register, name='auth-register'),
    path('login/', views.login, name='auth-login'),
    path('logout/', views.logout, name='auth-logout'),
    path('refresh/', views.refresh_token, name='auth-refresh'),
    
    # Session
    path('session/validate/', views.validate_session, name='auth-validate-session'),
    
    # Profile
    path('profile/', views.profile, name='auth-profile'),
    path('profile/update/', views.update_profile, name='auth-update-profile'),
    
    # Agent Access
    path('access/', views.agent_access, name='auth-agent-access'),
    
    # Invitations
    path('invitations/', views.InvitationListCreateView.as_view(), name='auth-invitations'),
    path('invitations/accept/', views.accept_invitation, name='auth-accept-invitation'),
    
    # Password Reset
    path('password/reset/', views.request_password_reset, name='auth-password-reset'),
    
    # Debug endpoints (remove in production)
    path('debug/', views_debug.debug_auth, name='auth-debug'),
    path('verify-token/', views_debug.verify_token_direct, name='auth-verify-token'),
]
