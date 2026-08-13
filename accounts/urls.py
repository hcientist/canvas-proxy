from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("login/canvas/start", views.canvas_login_start, name="canvas_start"),
    path("login/canvas/callback", views.canvas_login_callback, name="canvas_callback"),
    path("logout/", views.logout_view, name="logout"),
]
