from django.urls import path
from kalvi.api.views import SignInEndPoint, SignUpEndPoint, UserProfileView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView



urlpatterns = [
    path(
        "sign-up/",
        SignUpEndPoint.as_view(),
        name="kalvi-sign-up",
    ),
    path(
        "sign-in/",
        SignInEndPoint.as_view(),
        name="kalvi-sign-in",
    ),
    path(
        "profile/",
        UserProfileView.as_view(),
        name="UserDetail",
    ),
    path(
        "changepassword/",
        UserChangePasswordView.as_view(),
        name="password_change",
    ),
    path(
        "send-reset-password-email/",
        SendPasswordResetEmailView.as_view(),
        name="SendResetEmail",
    ),
    path(
        "reset-password/<uid>/<token>/",
        UserPasswordResetView.as_view(),
        name="ResetPasswordThroghMail",
    )
]
