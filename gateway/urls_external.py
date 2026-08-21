from django.urls import re_path

from . import views

app_name = "gateway_external"

urlpatterns = [
    # Anonymous access for external apps that opt in.  The client_id in the
    # path identifies the app; the Origin header gates access.
    re_path(
        r"^public/(?P<client_id>[0-9a-f]{32})/(?P<upstream_path>.*)$",
        views.anonymous_external_proxy,
        name="public_proxy",
    ),
    # Everything under /ext/ is appended to the calling app's registered API
    # base URL, so /ext/items with a base of https://api.example.com/v2
    # becomes https://api.example.com/v2/items.
    re_path(r"^(?P<upstream_path>.*)$", views.external_proxy, name="proxy"),
]
