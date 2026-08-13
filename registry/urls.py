from django.urls import path

from . import views

app_name = "registry"

urlpatterns = [
    path("", views.home, name="home"),
    path("healthz", views.healthz, name="healthz"),
    path("apps/", views.app_list, name="app_list"),
    path("apps/new", views.app_create, name="app_create"),
    path("apps/<int:pk>/", views.app_detail, name="app_detail"),
    path("apps/<int:pk>/edit", views.app_edit, name="app_edit"),
    path("apps/<int:pk>/submit", views.app_submit, name="app_submit"),
    path("apps/<int:pk>/rotate-secret", views.app_rotate_secret, name="app_rotate_secret"),
    path("apps/<int:pk>/revoke-grants", views.app_revoke_grants, name="app_revoke_grants"),
    path("apps/<int:pk>/delete", views.app_delete, name="app_delete"),
    path("review/", views.review_queue, name="review_queue"),
    path("review/<int:pk>/", views.review_app, name="review_app"),
]
