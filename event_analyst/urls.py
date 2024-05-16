from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("event_analyst_api.urls")),
    path(
        "api/password_reset/",
        include("django_rest_passwordreset.urls", namespace="password_reset"),
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
