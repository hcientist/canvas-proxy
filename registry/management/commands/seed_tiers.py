"""Create or update the three access tiers, one per Canvas developer key.

Credentials are read from the environment so secrets never sit in the repo:

    CANVAS_KEY_READ_BASIC_ID / CANVAS_KEY_READ_BASIC_SECRET
    CANVAS_KEY_READ_WRITE_ID / CANVAS_KEY_READ_WRITE_SECRET
    CANVAS_KEY_FULL_ID      / CANVAS_KEY_FULL_SECRET

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
        "slug": "read_basic",
        "name": "Read-only",
        "sort_order": 10,
        "description": (
            "Read access to the signed-in user's own profile, courses, "
            "enrolments and coursework. No writes of any kind."
        ),
        "allowed_methods": ["GET", "HEAD"],
        "path_rules": [
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/self(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/courses(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/calendar_events(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/announcements(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/planner(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/enrollment_terms(/|$)"},
        ],
        "denied_patterns": [
            r"^/api/graphql",
            r"^/api/v1/accounts(/|$)",
            r"^/api/v1/users/\d+/logins",
        ],
        "scopes": [
            "url:GET|/api/v1/users/:user_id/profile",
            "url:GET|/api/v1/users/:user_id/courses",
            "url:GET|/api/v1/courses",
            "url:GET|/api/v1/courses/:id",
            "url:GET|/api/v1/courses/:course_id/assignments",
            "url:GET|/api/v1/courses/:course_id/assignments/:id",
            "url:GET|/api/v1/courses/:course_id/enrollments",
            "url:GET|/api/v1/courses/:course_id/modules",
            "url:GET|/api/v1/courses/:course_id/pages",
        ],
        "allow_masquerade": False,
    },
    {
        "slug": "read_write",
        "name": "Read/write (course scope)",
        "sort_order": 20,
        "description": (
            "Full read and write access to courses the user can already reach: "
            "assignments, submissions, grades, pages, files and groups. "
            "Account-level endpoints and GraphQL stay closed."
        ),
        "allowed_methods": WRITE_METHODS,
        "path_rules": [
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/courses(/|$)"},
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/groups(/|$)"},
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/files(/|$)"},
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/folders(/|$)"},
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/calendar_events(/|$)"},
            {"methods": WRITE_METHODS, "pattern": r"^/api/v1/conversations(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/users/self(/|$)"},
            {"methods": ["GET", "HEAD"], "pattern": r"^/api/v1/enrollment_terms(/|$)"},
        ],
        "denied_patterns": [
            r"^/api/graphql",
            r"^/api/v1/accounts(/|$)",
            r"^/api/v1/users/\d+/logins",
            r"^/api/v1/.*/sis_imports",
        ],
        "scopes": [
            "url:GET|/api/v1/users/:user_id/profile",
            "url:GET|/api/v1/courses",
            "url:GET|/api/v1/courses/:id",
            "url:GET|/api/v1/courses/:course_id/assignments",
            "url:POST|/api/v1/courses/:course_id/assignments",
            "url:PUT|/api/v1/courses/:course_id/assignments/:id",
            "url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions",
            "url:PUT|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id",
            "url:GET|/api/v1/courses/:course_id/enrollments",
            "url:GET|/api/v1/courses/:course_id/pages",
            "url:PUT|/api/v1/courses/:course_id/pages/:url_or_id",
        ],
        "allow_masquerade": False,
    },
    {
        "slug": "full",
        "name": "Full API",
        "sort_order": 30,
        "description": (
            "Everything the developer key itself allows, including "
            "account-level endpoints, GraphQL and acting-as. Approve sparingly."
        ),
        "allowed_methods": [],
        "path_rules": [],
        "denied_patterns": [],
        "scopes": [],
        "enforces_scopes": False,
        "allow_masquerade": True,
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
