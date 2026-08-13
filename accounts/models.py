from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """A developer (or staff reviewer) who signs in through Canvas.

    Staff accounts created with `createsuperuser` keep working with a password;
    Canvas accounts get a synthetic username of the form `canvas-<id>`.
    """

    canvas_user_id = models.CharField(
        max_length=64,
        blank=True,
        unique=True,
        null=True,
        help_text="Canvas user id this account is bound to.",
    )
    canvas_login_id = models.CharField(max_length=255, blank=True)
    canvas_name = models.CharField(max_length=255, blank=True)
    canvas_avatar_url = models.URLField(blank=True, max_length=500)
    last_canvas_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_user"

    def __str__(self):
        return self.canvas_name or self.get_username()

    @property
    def display_name(self):
        return self.canvas_name or self.get_full_name() or self.get_username()

    @property
    def is_canvas_linked(self):
        return bool(self.canvas_user_id)
