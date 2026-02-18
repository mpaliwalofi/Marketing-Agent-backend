"""
Clean URL configuration for tenants - Production Ready.
Only includes necessary endpoints for subscription-based agent access.
"""

from django.urls import path
from . import views
from .views_with_auth import AgentProxyWithAuthView, AgentStatusWithAuthView

urlpatterns = [
    # ==================== AGENT PROXY (For Web Users) ====================
    # These are the main endpoints your Vercel website will use
    path('v2/agents/mark/chat/', AgentProxyWithAuthView.as_view(), name='agent-proxy-mark'),
    path('v2/agents/hr/chat/', AgentProxyWithAuthView.as_view(), name='agent-proxy-hr'),
    path('v2/agents/status/', AgentStatusWithAuthView.as_view(), name='agent-status'),
    
    # ==================== ADMIN ENDPOINTS ====================
    # These are for your internal admin use (managing subscriptions)
    
    # Tenant Management
    path('', views.TenantListCreateView.as_view(), name='tenant-list-create'),
    path('<uuid:tenant_id>/', views.TenantDetailView.as_view(), name='tenant-detail'),
    
    # Agent Configuration (set n8n/AWS endpoints)
    path('<uuid:tenant_id>/agents/', views.AgentConfigListCreateView.as_view(), name='agent-config-list'),
    path('<uuid:tenant_id>/agents/<int:config_id>/', views.AgentConfigDetailView.as_view(), name='agent-config-detail'),
    
    # Subscription Management
    path('<uuid:tenant_id>/subscription/', views.SubscriptionUpdateView.as_view(), name='subscription-update'),
    
    # ==================== OPTIONAL ENDPOINTS ====================
    # Uncomment if you need these features
    
    # Health Check
    # path('<uuid:tenant_id>/agents/<str:agent_type>/health/', views.AgentHealthCheckView.as_view(), name='agent-health-check'),
    
    # Statistics (for admin dashboard)
    # path('<uuid:tenant_id>/stats/', views.tenant_stats, name='tenant-stats'),
    
    # Request Logs (for debugging)
    # path('<uuid:tenant_id>/logs/', views.RequestLogListView.as_view(), name='request-logs'),
]
