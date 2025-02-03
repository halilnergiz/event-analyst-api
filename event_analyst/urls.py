from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings
from knox import views as knox_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("api.urls")),
    path(
        "api/password_reset/",
        include("django_rest_passwordreset.urls", namespace="password_reset"),
    ),
    path("api/auth/", include("knox.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
