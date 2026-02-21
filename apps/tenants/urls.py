"""
URL configuration for tenants app (agent proxy endpoints).
"""

from django.urls import path
from . import views

urlpatterns = [
    # Agent proxy — JWT or API key auth
    path("<str:agent_type>/chat/", views.AgentProxyView.as_view(), name="agent-proxy"),
    path("status/", views.AgentStatusView.as_view(), name="agent-status"),
]
