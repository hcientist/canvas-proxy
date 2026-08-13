FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=config.settings

WORKDIR /app

# libpq is needed by psycopg; curl backs the compose healthcheck.
RUN apt-get update \
    && apt-get install --no-install-recommends -y libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-docker.txt ./
RUN pip install -r requirements-docker.txt

COPY . .

RUN useradd --create-home --uid 10001 app

# collectstatic runs at build time so the image is self-contained and the
# container needs no writable static directory at runtime. The manifest storage
# backend requires a settings module that imports cleanly, hence the dummy key.
RUN DJANGO_SECRET_KEY=build-only TOKEN_ENCRYPTION_KEY=build-only \
    python manage.py collectstatic --noinput \
    && chown -R app:app /app/staticfiles

USER app

EXPOSE 8000

# Checks the body, not just the status: a redirect or an error page would
# otherwise satisfy a bare `curl -f`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz | grep -q '"status": "ok"' || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
