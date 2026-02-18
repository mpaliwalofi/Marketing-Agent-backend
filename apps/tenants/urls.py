"""
URL configuration for tenants app.
"""

from django.urls import path
from . import views
from .views_with_auth import AgentProxyWithAuthView, AgentStatusWithAuthView

urlpatterns = [
    # =============================================================================
    # Tenant Management
    # =============================================================================
    path('', views.TenantListCreateView.as_view(), name='tenant-list-create'),
    path('<uuid:tenant_id>/', views.TenantDetailView.as_view(), name='tenant-detail'),
    
    # =============================================================================
    # Agent Configuration
    # =============================================================================
    path('<uuid:tenant_id>/agents/', views.AgentConfigListCreateView.as_view(), name='agent-config-list'),
    path('<uuid:tenant_id>/agents/<int:config_id>/', views.AgentConfigDetailView.as_view(), name='agent-config-detail'),
    path('<uuid:tenant_id>/agents/<str:agent_type>/health/', views.AgentHealthCheckView.as_view(), name='agent-health-check'),
    
    # =============================================================================
    # API Key Management
    # =============================================================================
    path('<uuid:tenant_id>/keys/', views.APIKeyListCreateView.as_view(), name='apikey-list-create'),
    path('<uuid:tenant_id>/keys/<uuid:key_id>/revoke/', views.APIKeyRevokeView.as_view(), name='apikey-revoke'),
    
    # =============================================================================
    # Subscription Management
    # =============================================================================
    path('<uuid:tenant_id>/subscription/', views.SubscriptionUpdateView.as_view(), name='subscription-update'),
    
    # =============================================================================
    # Request Logs
    # =============================================================================
    path('<uuid:tenant_id>/logs/', views.RequestLogListView.as_view(), name='request-logs'),
    
    # =============================================================================
    # Stats
    # =============================================================================
    path('<uuid:tenant_id>/stats/', views.tenant_stats, name='tenant-stats'),
    
    # =============================================================================
    # API Key Validation
    # =============================================================================
    path('validate-key/', views.validate_api_key, name='validate-api-key'),
    
    # =============================================================================
    # Agent Proxy (Main API for Tenants - requires API key)
    # =============================================================================
    path('agents/<str:agent_type>/chat/', views.AgentProxyView.as_view(), name='agent-proxy'),
    path('agents/status/', views.AgentStatusView.as_view(), name='agent-status'),
    
    # =============================================================================
    # Agent Proxy with Auth (Supports both Supabase JWT and API Key)
    # =============================================================================
    path('v2/agents/<str:agent_type>/chat/', AgentProxyWithAuthView.as_view(), name='agent-proxy-v2'),
    path('v2/agents/status/', AgentStatusWithAuthView.as_view(), name='agent-status-v2'),
]
