"""Developer dashboard and the staff review queue."""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db import connection
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from gateway.models import RequestLog
from oauth.models import CanvasGrant

from .forms import ProxyAppForm, ReviewForm
from .models import AccessTier, AppStatus, ProxyApp

staff_required = user_passes_test(lambda u: u.is_authenticated and u.is_staff)

# Editing any of these invalidates the basis on which the app was approved.
REVIEW_TRIGGERING_FIELDS = {"redirect_uris", "tier", "is_public_client"}


def home(request):
    return render(
        request,
        "registry/home.html",
        {
            "tiers": AccessTier.objects.filter(is_active=True),
            "canvas_base_url": settings.CANVAS_BASE_URL,
            "proxy_base_url": settings.PROXY_BASE_URL,
        },
    )


def healthz(request):
    """Liveness probe for the container orchestrator. Never cached."""
    try:
        connection.ensure_connection()
    except Exception as exc:  # noqa: BLE001 - report, don't raise, to the probe
        return JsonResponse({"status": "error", "database": str(exc)}, status=503)

    configured = AccessTier.objects.filter(is_active=True).exclude(
        canvas_client_id=""
    ).count()
    response = JsonResponse(
        {"status": "ok", "database": "ok", "configured_tiers": configured}
    )
    response["Cache-Control"] = "no-store"
    return response


@login_required
def app_list(request):
    apps = (
        ProxyApp.objects.filter(owner=request.user)
        .select_related("tier")
        .annotate(
            active_grants=Count("grants", filter=Q(grants__revoked_at__isnull=True))
        )
    )
    return render(request, "registry/app_list.html", {"apps": apps})


@login_required
def app_create(request):
    if request.method == "POST":
        form = ProxyAppForm(request.POST)
        if form.is_valid():
            app = form.save(commit=False)
            app.owner = request.user
            app.status = AppStatus.DRAFT
            app.save()
            if not app.is_public_client:
                _stash_secret(request, app, app.rotate_secret())
            messages.success(
                request,
                "App created. Review the details, then submit it for approval.",
            )
            return redirect("registry:app_detail", pk=app.pk)
    else:
        form = ProxyAppForm()
    return render(request, "registry/app_form.html", {"form": form, "app": None})


@login_required
def app_detail(request, pk):
    app = get_object_or_404(
        ProxyApp.objects.select_related("tier", "owner", "reviewed_by"), pk=pk
    )
    if app.owner_id != request.user.pk and not request.user.is_staff:
        return _not_yours(request)

    grants = (
        CanvasGrant.objects.filter(app=app, revoked_at__isnull=True)
        .order_by("-created_at")[:25]
    )
    recent_calls = RequestLog.objects.filter(app=app)[:25]

    return render(
        request,
        "registry/app_detail.html",
        {
            "app": app,
            "grants": grants,
            "recent_calls": recent_calls,
            "revealed_secret": _pop_secret(request, app),
            "proxy_base_url": settings.PROXY_BASE_URL,
            "canvas_base_url": settings.CANVAS_BASE_URL,
            "can_edit": app.owner_id == request.user.pk,
        },
    )


@login_required
def app_edit(request, pk):
    app = get_object_or_404(ProxyApp, pk=pk, owner=request.user)
    if request.method == "POST":
        form = ProxyAppForm(request.POST, instance=app)
        if form.is_valid():
            sensitive_change = REVIEW_TRIGGERING_FIELDS & set(form.changed_data)
            app = form.save()
            if sensitive_change and app.status == AppStatus.APPROVED:
                # An approval covers a specific tier and redirect list; changing
                # either means the approval no longer describes this app.
                app.submit_for_review()
                app.save(
                    update_fields=[
                        "status",
                        "submitted_at",
                        "reviewed_by",
                        "reviewed_at",
                    ]
                )
                messages.warning(
                    request,
                    "Changing "
                    + ", ".join(sorted(sensitive_change))
                    + " sent this app back for review. Existing tokens keep working "
                    "until a reviewer decides.",
                )
            else:
                messages.success(request, "App updated.")
            return redirect("registry:app_detail", pk=app.pk)
    else:
        form = ProxyAppForm(instance=app)
    return render(request, "registry/app_form.html", {"form": form, "app": app})


@login_required
@require_http_methods(["POST"])
def app_submit(request, pk):
    app = get_object_or_404(ProxyApp, pk=pk, owner=request.user)
    if app.status == AppStatus.SUSPENDED:
        messages.error(
            request, "Suspended apps cannot be resubmitted. Contact an administrator."
        )
        return redirect("registry:app_detail", pk=app.pk)
    if not app.redirect_uris:
        messages.error(request, "Add at least one redirect URI first.")
        return redirect("registry:app_detail", pk=app.pk)

    app.submit_for_review()
    app.save(update_fields=["status", "submitted_at", "reviewed_by", "reviewed_at"])
    messages.success(request, "Submitted for review.")
    return redirect("registry:app_detail", pk=app.pk)


@login_required
@require_http_methods(["POST"])
def app_rotate_secret(request, pk):
    app = get_object_or_404(ProxyApp, pk=pk, owner=request.user)
    if app.is_public_client:
        messages.error(request, "Public clients do not have a secret.")
        return redirect("registry:app_detail", pk=app.pk)

    _stash_secret(request, app, app.rotate_secret())
    messages.warning(
        request, "New secret issued. The previous secret stopped working immediately."
    )
    return redirect("registry:app_detail", pk=app.pk)


@login_required
@require_http_methods(["POST"])
def app_revoke_grants(request, pk):
    app = get_object_or_404(ProxyApp, pk=pk, owner=request.user)
    count = 0
    for grant in app.grants.filter(revoked_at__isnull=True).select_related("tier"):
        grant.revoke(at_canvas=True)
        count += 1
    messages.success(request, f"Revoked {count} Canvas grant(s).")
    return redirect("registry:app_detail", pk=app.pk)


@login_required
@require_http_methods(["POST"])
def app_delete(request, pk):
    app = get_object_or_404(ProxyApp, pk=pk, owner=request.user)
    for grant in app.grants.filter(revoked_at__isnull=True).select_related("tier"):
        grant.revoke(at_canvas=True)
    name = app.name
    app.delete()
    messages.success(request, f"Deleted {name} and revoked its Canvas grants.")
    return redirect("registry:app_list")


# --- staff review -----------------------------------------------------------


@staff_required
def review_queue(request):
    pending = (
        ProxyApp.objects.filter(status=AppStatus.PENDING)
        .select_related("tier", "owner")
        .order_by("submitted_at")
    )
    decided = (
        ProxyApp.objects.exclude(status__in=[AppStatus.PENDING, AppStatus.DRAFT])
        .select_related("tier", "owner", "reviewed_by")
        .order_by("-reviewed_at")[:25]
    )
    return render(
        request,
        "registry/review_queue.html",
        {"pending": pending, "decided": decided},
    )


@staff_required
def review_app(request, pk):
    app = get_object_or_404(
        ProxyApp.objects.select_related("tier", "owner"), pk=pk
    )
    sibling_apps = (
        ProxyApp.objects.filter(owner=app.owner).exclude(pk=app.pk).select_related("tier")
    )

    if request.method == "POST":
        form = ReviewForm(request.POST)
        if form.is_valid():
            decision = form.cleaned_data["decision"]
            notes = form.cleaned_data["notes"]
            if decision == "approve":
                app.approve(request.user, notes)
                messages.success(request, f"Approved {app.name}.")
            elif decision == "reject":
                app.reject(request.user, notes)
                messages.success(request, f"Rejected {app.name}.")
            else:
                app.suspend(request.user, notes)
                messages.warning(
                    request,
                    f"Suspended {app.name} and revoked every Canvas grant it held.",
                )
            return redirect("registry:review_queue")
    else:
        form = ReviewForm()

    return render(
        request,
        "registry/review_app.html",
        {
            "app": app,
            "form": form,
            "sibling_apps": sibling_apps,
            "active_grants": app.grants.filter(revoked_at__isnull=True).count(),
            "recent_calls": RequestLog.objects.filter(app=app)[:20],
        },
    )


# --- helpers ----------------------------------------------------------------


def _not_yours(request):
    messages.error(request, "That app belongs to someone else.")
    return redirect("registry:app_list")


def _secret_session_key(app):
    return f"revealed_secret:{app.pk}"


def _stash_secret(request, app, secret):
    """Hold a freshly minted secret for exactly one page render."""
    request.session[_secret_session_key(app)] = secret


def _pop_secret(request, app):
    return request.session.pop(_secret_session_key(app), None)
