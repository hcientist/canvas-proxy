from django.urls import path

from . import views

app_name = "oauth"

urlpatterns = [
    path("auth", views.authorize, name="authorize"),
    path("auth/<uuid:request_id>/confirm", views.authorize_confirm, name="confirm"),
    path("canvas/callback", views.canvas_callback, name="canvas_callback"),
    path("token", views.token, name="token"),
    path("revoke", views.revoke, name="revoke"),
    path("metadata", views.metadata, name="metadata"),
]
