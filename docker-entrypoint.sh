#!/usr/bin/env bash
# Prepares the database, then hands off to the process in CMD.
set -euo pipefail

if [ -n "${DATABASE_URL:-}" ]; then
  echo "waiting for the database..."
  for attempt in $(seq 1 60); do
    if python -c "
import django, sys
django.setup()
from django.db import connection
try:
    connection.ensure_connection()
except Exception:
    sys.exit(1)
" 2>/dev/null; then
      break
    fi
    if [ "$attempt" -eq 60 ]; then
      echo "database did not come up in time" >&2
      exit 1
    fi
    sleep 1
  done
fi

echo "applying migrations..."
python manage.py migrate --noinput

# Creates the three tiers if absent and refreshes credentials from the
# environment. Existing tier rules are left alone.
echo "seeding access tiers..."
python manage.py seed_tiers

exec "$@"
