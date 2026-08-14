from django.contrib import admin
from django.urls import include, path

from oauth import views as oauth_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("oauth2/", include("oauth.urls")),
    path(
        ".well-known/oauth-authorization-server",
        oauth_views.metadata,
        name="oauth-metadata",
    ),
    # Canvas SDKs commonly point at /login/oauth2/*; accept those spellings too
    # so an existing client can be repointed by changing only its base URL.
    path("login/oauth2/auth", oauth_views.canvas_style_authorize),
    path("login/oauth2/token", oauth_views.canvas_style_token),
    path("api/", include("gateway.urls")),
    # Dashboard routes are last: they own the remaining namespace.
    path("", include("registry.urls")),
]
