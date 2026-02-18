from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse


def home_view(request):
    return HttpResponse("<h1>SIA API</h1><p>Backend is running.</p>")


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.auth_app.urls')),
    path('api/waitlist/', include('apps.waitlist.urls')),
    path('api/chat/', include('apps.chatbot.urls')),
    path('api/tenants/', include('apps.tenants.urls')),
    path('', home_view),
]