"""
Clean URL configuration for auth app - Production Ready.
Only includes necessary endpoints for web users.
"""

from django.urls import path
from . import views

urlpatterns = [
    # ==================== AUTHENTICATION ====================
    # User Registration & Login
    path('register/', views.register, name='auth-register'),
    path('login/', views.login, name='auth-login'),
    path('logout/', views.logout, name='auth-logout'),
    path('refresh/', views.refresh_token, name='auth-refresh'),
    
    # Session Validation
    path('session/validate/', views.validate_session, name='auth-validate-session'),
    
    # User Profile
    path('profile/', views.profile, name='auth-profile'),
    path('profile/update/', views.update_profile, name='auth-update-profile'),
    
    # Agent Access Check
    path('access/', views.agent_access, name='auth-agent-access'),
    
    # ==================== PASSWORD MANAGEMENT ====================
    path('password/reset/', views.request_password_reset, name='auth-password-reset'),
    
    # ==================== INVITATIONS (Optional) ====================
    # Uncomment if you need team invitations
    # path('invitations/', views.InvitationListCreateView.as_view(), name='auth-invitations'),
    # path('invitations/accept/', views.accept_invitation, name='auth-accept-invitation'),
]
