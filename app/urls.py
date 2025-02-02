from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("", views.index, name="index"),
    path("register/", views.register, name="register"),
    path("verify/<str:token>/", views.verify_email, name="verify_email"),
    path("login/", views.login_user, name="login"),
    path("logout/", views.logout_user, name="logout"),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path("reset-password/<str:token>/", views.reset_password, name="reset_password"),

    path("profile/", views.profile, name="profile"),
    path("edit_profile/", views.edit_profile, name="edit_profile"),

    path("admin-profile/", views.admin_profile, name="admin_profile"),
    path("admin_edit_profile/", views.admin_edit_profile, name="admin_edit_profile"),
    path("users_list/", views.users_list, name="users_list"),
    path("toggle_user_status/<int:user_id>/", views.toggle_user_status, name="toggle_user_status"),

    path("staff-profile/", views.staff_profile, name="staff_profile"),
    path("staff_edit_profile/", views.staff_edit_profile, name="staff_edit_profile"),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
+static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
