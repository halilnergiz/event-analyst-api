from django.urls import path
from .views import (
    register_user,
    user_login,
    user_logout,
    change_password,
    VerifyEmail,
    get_user_info,
    ResendActivationEmail,
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
]