from django.urls import path
from django.conf.urls.static import static
from django.conf import settings

from .views import (
    register_user,
    user_login,
    user_logout,
    change_password,
    VerifyEmail,
    get_user_info,
    ResendActivationEmail,
    create_event,
    delete_event,
    get_all_events,
    update_event,
    partial_update_event,
    PhotoCreateAPIView,
)

urlpatterns = [
    path("register/", register_user, name="register"),
    path("login/", user_login, name="login"),
    path("logout/", user_logout, name="logout"),
    path("change_password/", change_password, name="change_password"),
    path("email_verify/", VerifyEmail.as_view(), name="email_verify"),
    path("get_user_info/<str:email>/", get_user_info, name="get_user_info"),
    path(
        "resend_email_verify/",
        ResendActivationEmail.as_view(),
        name="resend_email_verify",
    ),
    path("create_event/", create_event, name="create_event"),
    path("delete_event/<str:event_id>/", delete_event, name="delete_event"),
    path("get_all_events/", get_all_events, name="get_all_events"),
    path("update_event/<str:event_id>/", update_event, name="update_event"),
    path(
        "partial_update_event/<str:event_id>/",
        partial_update_event,
        name="partial_update_event",
    ),
    path(
        "upload_photo/",
        PhotoCreateAPIView.as_view(),
        name="upload_photo",
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
