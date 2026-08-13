#!/usr/bin/env bash
# End-to-end check: runs a stand-in Canvas, a real Django server, and drives the
# whole authorization chain over HTTP. Nothing here touches your real database
# or a real Canvas instance.
#
#   ./tools/e2e/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
WORK="$(mktemp -d)"
trap 'kill ${CANVAS_PID:-} ${PROXY_PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT

export DJANGO_SETTINGS_MODULE=config.settings
export DJANGO_DEBUG=1
export DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
export PROXY_BASE_URL=http://127.0.0.1:8099
export CANVAS_BASE_URL=http://127.0.0.1:9911
export SQLITE_PATH="$WORK/e2e.sqlite3"
export TOKEN_ENCRYPTION_KEY="$("$PYTHON" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

cd "$ROOT"

"$PYTHON" manage.py migrate -v0
"$PYTHON" manage.py seed_tiers -v0

# One approved read-only app, owned by a throwaway developer.
"$PYTHON" - <<'PY' > "$WORK/creds.txt"
import django
django.setup()
from django.contrib.auth import get_user_model
from registry.models import AccessTier, ProxyApp

User = get_user_model()
staff = User.objects.create_user(username="reviewer", password="pw", is_staff=True)
dev = User.objects.create_user(username="dev", canvas_user_id="7", canvas_name="Dev Person")

tier = AccessTier.objects.get(slug="read_basic")
tier.canvas_client_id = "10000000000001"
tier.canvas_client_secret = "canvas-key-secret"
tier.save()

app = ProxyApp(
    owner=dev, tier=tier, name="Gradebook Sync",
    description="Syncs grades.", redirect_uris=["http://localhost:3000/callback"],
)
app.save()
secret = app.rotate_secret()
app.approve(staff, "ok")
print(app.client_id)
print(secret)
PY

"$PYTHON" tools/e2e/fake_canvas.py > "$WORK/canvas.log" 2>&1 &
CANVAS_PID=$!
"$PYTHON" manage.py runserver 127.0.0.1:8099 --noreload > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
  if curl -sf -o /dev/null "http://127.0.0.1:8099/" && \
     curl -s -o /dev/null "http://127.0.0.1:9911/api/v1/ping"; then
    break
  fi
  sleep 0.5
done

"$PYTHON" tools/e2e/e2e.py "$(sed -n 1p "$WORK/creds.txt")" "$(sed -n 2p "$WORK/creds.txt")"
