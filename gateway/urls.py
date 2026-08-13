from django.urls import re_path

from . import views

app_name = "gateway"

urlpatterns = [
    # Everything under /api/ maps to the same path on the Canvas host, so
    # /api/v1/courses here is /api/v1/courses there.
    re_path(r"^(?P<upstream_path>.*)$", views.proxy, name="proxy"),
]
