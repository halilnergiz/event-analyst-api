from django.urls import path

from knox import views as knox_views

from .views import (
    CreateUserView,
    LoginUserView,
    ManageUserView,
    change_password,
    VerifyEmailView,
    ResendActivationEmailView,
    create_event,
    delete_event,
    EventDetailView,
    create_event_statistic,
    update_event_statistic,
    get_all_events,
    update_event,
    partial_update_event,
    EventPhotosListView,
    PhotoCreateView,
    PhotoDetailView,
    PhotoDeleteView,
    PhotoCreateView,
)


urlpatterns = [
    path("register/", CreateUserView.as_view(), name="register"),
    path("login/", LoginUserView.as_view(), name="knox_login"),
    path("profile/", ManageUserView.as_view(), name="profile"),
    path("logout/", knox_views.LogoutView.as_view(), name="knox_logout"),
    path("logoutall/", knox_views.LogoutAllView.as_view(), name="knox_logoutall"),
    path("change_password/", change_password, name="change_password"),
    path("email_verify/", VerifyEmailView.as_view(), name="email_verify"),
    path(
        "resend_email_verify/",
        ResendActivationEmailView.as_view(),
        name="resend_email_verify",
    ),
    path("create_event/", create_event, name="create_event"),
    path(
        "create_event_statistic/<uuid:event_id>/",
        create_event_statistic,
        name="create_event_statistic",
    ),
    path(
        "update_event_statistic/<uuid:event_id>/",
        update_event_statistic,
        name="update_event_statistic",
    ),
    path("event_detail/<str:eventId>/", EventDetailView.as_view(), name="event_detail"),
    path("get_all_events/", get_all_events, name="get_all_events"),
    path("update_event/<str:event_id>/", update_event, name="update_event"),
    path(
        "partial_update_event/<str:event_id>/",
        partial_update_event,
        name="partial_update_event",
    ),
    path("delete_event/<str:event_id>/", delete_event, name="delete_event"),
    path("photos/upload/", PhotoCreateView.as_view(), name="photo_upload"),
    path("photos/<uuid:photoId>/", PhotoDetailView.as_view(), name="photo_detail"),
    path(
        "events/<uuid:eventId>/photos/",
        EventPhotosListView.as_view(),
        name="event_photos_list",
    ),
    path(
        "photos/<uuid:photoId>/delete/",
        PhotoDeleteView.as_view(),
        name="photo_delete",
    ),
]
