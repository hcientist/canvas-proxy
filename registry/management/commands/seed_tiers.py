"""Create or update the three access tiers, one per Canvas developer key.

Credentials are read from the environment so secrets never sit in the repo:

    CANVAS_KEY_AUTH_ONLY_ID  / CANVAS_KEY_AUTH_ONLY_SECRET
    CANVAS_KEY_READ_ONLY_ID  / CANVAS_KEY_READ_ONLY_SECRET
    CANVAS_KEY_READ_WRITE_ID / CANVAS_KEY_READ_WRITE_SECRET

Re-running is safe: path rules and scopes are only written when the tier is
first created, so local edits survive. Pass --reset-rules to overwrite them.
"""

import os

from django.core.management.base import BaseCommand

from registry.models import AccessTier

WRITE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

# The `pattern` values are regexes matched against the upstream path, e.g.
# "/api/v1/courses/123/assignments".
TIERS = [
    {
        "slug": "auth_only",
        "name": "Auth only",
        "sort_order": 10,
        "description": (
            "Identity only: the signed-in user's profile. "
            "No course data, no writes."
        ),
        "allowed_methods": ["GET", "HEAD"],
        "path_rules": [
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/self(/|$)"},
        ],
        "denied_patterns": [
            r"^/api/graphql",
            r"^/api/v1/accounts(/|$)",
            r"^/api/v1/courses(/|$)",
        ],
        "scopes": [
            "url:GET|/api/v1/users/:user_id/profile",
        ],
        "allow_masquerade": False,
    },
    {
        "slug": "read_only",
        "name": "Read-only",
        "sort_order": 20,
        "description": (
            "Read access to the signed-in user's profile, courses, "
            "enrolments, sections and avatars. No writes of any kind."
        ),
        "allowed_methods": ["GET", "HEAD"],
        "path_rules": [
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/self(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/\d+/profile(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/\d+/enrollments(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/\d+/avatars(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/courses(/|$)"},
        ],
        "denied_patterns": [
            r"^/api/graphql",
            r"^/api/v1/accounts(/|$)",
            r"^/api/v1/users/\d+/logins",
        ],
        "scopes": [
            "url:GET|/api/v1/courses",
            "url:GET|/api/v1/courses/:id",
            "url:GET|/api/v1/users/:user_id/enrollments",
            "url:GET|/api/v1/courses/:course_id/sections",
            "url:GET|/api/v1/users/:user_id/avatars",
            "url:GET|/api/v1/users/:user_id/profile",
        ],
        "allow_masquerade": False,
    },
    {
        "slug": "read_write",
        "name": "Read/write",
        "sort_order": 30,
        "description": (
            "Read and write access to courses, assignments, and enrolments. "
            "Includes account-level course creation."
        ),
        "allowed_methods": WRITE_METHODS,
        "path_rules": [
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/courses(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/self(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/\d+/profile(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/\d+/enrollments(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/sections/\d+/enrollments(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/accounts/\d+/enrollments(/|$)"},
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/accounts/\d+/courses(/|$)"},
        ],
        "denied_patterns": [
            r"^/api/graphql",
            r"^/api/v1/users/\d+/logins",
            r"^/api/v1/.*/sis_imports",
        ],
        "scopes": [
            "url:GET|/api/v1/users/:user_id/profile",
            "url:GET|/api/v1/courses/:course_id/enrollments",
            "url:GET|/api/v1/sections/:section_id/enrollments",
            "url:GET|/api/v1/users/:user_id/enrollments",
            "url:GET|/api/v1/courses",
            "url:GET|/api/v1/accounts/:account_id/enrollments/:id",
            "url:POST|/api/v1/courses/:course_id/assignments",
            "url:PUT|/api/v1/courses/:course_id/assignments/:id",
            "url:GET|/api/v1/courses/:course_id/assignments/:id",
            "url:DELETE|/api/v1/courses/:course_id/assignments/:id",
            "url:POST|/api/v1/accounts/:account_id/courses",
            "url:PUT|/api/v1/courses/:id",
            "url:DELETE|/api/v1/courses/:id",
            "url:GET|/api/v1/courses/:id",
            "url:GET|/api/v1/accounts/:account_id/courses/:id",
        ],
        "allow_masquerade": False,
    },
]


class Command(BaseCommand):
    help = "Create or update the access tiers backing the three Canvas developer keys."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset-rules",
            action="store_true",
            help="Overwrite scopes and path rules on tiers that already exist.",
        )

    def handle(self, *args, **options):
        verbose = options["verbosity"] > 0
        for spec in TIERS:
            spec = dict(spec)
            slug = spec.pop("slug")
            env_prefix = f"CANVAS_KEY_{slug.upper()}"
            client_id = os.environ.get(f"{env_prefix}_ID", "")
            client_secret = os.environ.get(f"{env_prefix}_SECRET", "")

            tier, created = AccessTier.objects.get_or_create(
                slug=slug, defaults={"name": spec["name"]}
            )

            if created or options["reset_rules"]:
                for field, value in spec.items():
                    setattr(tier, field, value)
            else:
                # Keep operator edits; only refresh the prose.
                tier.name = spec["name"]
                tier.description = spec["description"]

            if client_id:
                tier.canvas_client_id = client_id
            if client_secret:
                tier.canvas_client_secret = client_secret
            tier.save()

            if verbose:
                state = "created" if created else "updated"
                creds = "credentials set" if tier.is_configured else "NO CREDENTIALS"
                style = self.style.SUCCESS if tier.is_configured else self.style.WARNING
                self.stdout.write(style(f"{slug}: {state}, {creds}"))

        if verbose:
            self.stdout.write("")
            self.stdout.write(
                "Each developer key in Canvas must list this redirect URI:\n"
                "  <PROXY_BASE_URL>/accounts/canvas/login/callback/"
            )
