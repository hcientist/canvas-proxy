#!/usr/bin/env bash
# End-to-end check against the real container image, using a stand-in Canvas.
# Verifies the built artifact -- gunicorn, whitenoise, Postgres, Redis, the
# entrypoint's migrate/seed -- not just the code.
#
#   ./tools/e2e/run-docker.sh
#
# Uses a separate compose project so it cannot touch a running deployment.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
PROJECT=canvas-proxy-smoke
COMPOSE=(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.smoke.yml)
WORK="$(mktemp -d)"

cd "$ROOT"
cleanup() {
  "${COMPOSE[@]}" --env-file "$WORK/.env" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network inspect web >/dev/null 2>&1 || docker network create web >/dev/null

# Both are needed: ENV_FILE feeds the compose env_file: directive, --env-file
# feeds ${...} interpolation inside the compose files themselves.
export ENV_FILE="$WORK/.env"

cat > "$WORK/.env" <<EOF
DJANGO_SECRET_KEY=$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(50))')
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,canvas-proxy
PROXY_BASE_URL=http://127.0.0.1:8099
CSRF_TRUSTED_ORIGINS=http://127.0.0.1:8099
CANVAS_BASE_URL=http://fake-canvas:9911
TOKEN_ENCRYPTION_KEY=$("$PYTHON" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
CANVAS_KEY_READ_BASIC_ID=10000000000001
CANVAS_KEY_READ_BASIC_SECRET=canvas-key-secret
CANVAS_LOGIN_TIER=read_basic
POSTGRES_PASSWORD=$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(24))')
# The harness drives the app over plain http, so TLS-only behaviour is off.
SECURE_SSL_REDIRECT=0
SECURE_COOKIES=0
EOF

echo "building and starting the stack..."
"${COMPOSE[@]}" --env-file "$WORK/.env" up -d --build

echo "waiting for the app to report healthy..."
for _ in $(seq 1 60); do
  status="$(docker inspect --format '{{.State.Health.Status}}' \
    "$("${COMPOSE[@]}" --env-file "$WORK/.env" ps -q canvas-proxy)" 2>/dev/null || echo starting)"
  [ "$status" = "healthy" ] && break
  sleep 2
done
if [ "${status:-}" != "healthy" ]; then
  echo "app never became healthy; logs follow" >&2
  "${COMPOSE[@]}" --env-file "$WORK/.env" logs canvas-proxy >&2
  exit 1
fi

echo "registering an approved app..."
"${COMPOSE[@]}" --env-file "$WORK/.env" exec -T canvas-proxy python - <<'PY' > "$WORK/creds.txt"
import django
django.setup()
from django.contrib.auth import get_user_model
from registry.models import AccessTier, ProxyApp

User = get_user_model()
staff = User.objects.create_user(username="reviewer", password="pw", is_staff=True)
dev = User.objects.create_user(username="dev", canvas_user_id="7", canvas_name="Dev Person")
app = ProxyApp(
    owner=dev, tier=AccessTier.objects.get(slug="read_basic"), name="Gradebook Sync",
    description="Syncs grades.", redirect_uris=["http://localhost:3000/callback"],
)
app.save()
secret = app.rotate_secret()
app.approve(staff, "ok")
print(app.client_id)
print(secret)
PY

PROXY_URL=http://127.0.0.1:8099 \
CANVAS_URL=http://fake-canvas:9911 \
CANVAS_FROM_HOST=http://127.0.0.1:9911 \
  "$PYTHON" tools/e2e/e2e.py "$(sed -n 1p "$WORK/creds.txt")" "$(sed -n 2p "$WORK/creds.txt")"
