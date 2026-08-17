from django.urls import re_path

from . import views

app_name = "gateway_external"

urlpatterns = [
    # Everything under /ext/ is appended to the calling app's registered API
    # base URL, so /ext/items with a base of https://api.example.com/v2
    # becomes https://api.example.com/v2/items.
    re_path(r"^(?P<upstream_path>.*)$", views.external_proxy, name="proxy"),
]
