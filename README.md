# Canvas API Proxy

A Django app that lets developers reach a Canvas instance's API without ever
holding a Canvas developer key.

You register three developer keys in Canvas — one per access tier — pointed at
this host. Developers then register their own "apps" here, choose a tier, and go
through review. Once approved, an app runs a normal OAuth2 authorization-code
flow against **this** host; the proxy performs the real Canvas flow behind it
with the tier's key, stores the resulting Canvas token, and forwards the app's
API calls upstream.

The app never sees a Canvas token. Revoking its approval cuts it off at once.

---

## How the pieces fit

```
 developer's app                this proxy                       Canvas
 ───────────────                ──────────                       ──────
  GET /oauth2/auth  ─────────►  validate client_id +
   client_id, redirect_uri      redirect_uri, show a
   state, (PKCE)                consent screen naming
                                the app
                                      │
                                      └─────────────────────►  /login/oauth2/auth
                                                                (tier's dev key)
                                                                      │
                                GET /oauth2/canvas/callback  ◄────────┘
                                exchange code for a real
                                Canvas token, store it
                                encrypted, mint our own
                                      │
  redirect_uri?code=… ◄───────────────┘

  POST /oauth2/token ────────►  verify client secret /
   code, client creds           PKCE, return a *proxy*
                                access + refresh token
  ◄──────────── access_token

  GET /api/v1/courses ───────►  check tier rules, swap in
   Authorization: Bearer …      the Canvas token, forward ──►  /api/v1/courses
  ◄──────────── response        rewrite pagination links   ◄──
```

Three credentials, kept strictly apart:

| Credential | Held by | Stored as |
|---|---|---|
| Canvas developer key secret | the proxy | Fernet-encrypted |
| Canvas access/refresh token | the proxy | Fernet-encrypted |
| Proxy access/refresh token | the app | HMAC-SHA256 digest only |

---

## Setup

### 1. Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env      # then edit it
```

Generate the encryption key that protects stored Canvas tokens:

```bash
.venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Create three developer keys in Canvas

In Canvas: **Admin → Developer Keys → + Developer Key → + API Key**. Create one
per tier. Each one needs:

- **Redirect URIs**: `https://your-proxy-host/oauth2/canvas/callback` — this one
  URI, on all three keys, in the multi-line *Redirect URIs* box rather than the
  legacy single-value field. Canvas matches it exactly, so a missing or extra
  trailing slash fails. `check_canvas_keys` below verifies this for you.
- **Scopes**: tick *Enforce Scopes* and select the scopes appropriate to that
  tier. The `full` tier's key is the one to leave unscoped, if you want one.

Put the key IDs and secrets in `.env` as `CANVAS_KEY_<TIER>_ID` / `_SECRET`.

### 3. Migrate and seed

```bash
set -a && . ./.env && set +a
.venv/bin/python manage.py migrate
.venv/bin/python manage.py seed_tiers      # reads the keys out of the environment
.venv/bin/python manage.py createsuperuser # your first staff reviewer
```

`seed_tiers` creates three tiers — `read_basic`, `read_write`, `full` — with
starter method and path rules. Re-running it refreshes credentials and
descriptions but leaves your rule edits alone; pass `--reset-rules` to overwrite.

### 4. Run

```bash
.venv/bin/python manage.py runserver
```

For production, see Docker below.

---

## Docker

```bash
cp .env.example .env      # fill in the domain, keys and passwords
docker compose up -d
```

Three containers: the app under gunicorn, Postgres, and Redis. The app joins the
external `web` network so a reverse proxy can reach it; Postgres and Redis stay
on a private network with no route in. Nothing is published to the host — the
only way in is through your proxy.

The entrypoint waits for Postgres, applies migrations, and runs `seed_tiers`, so
a fresh volume comes up ready. Static files are baked into the image at build
time and served by whitenoise, since the reverse proxy has no access to them.
`/healthz` backs the container healthcheck.

Create the shared network once if you don't already have it:

```bash
docker network create web
```

### Nginx Proxy Manager

Add a Proxy Host:

| Field | Value |
|---|---|
| Domain Names | `canvas-proxy.example.edu` |
| Scheme | `http` |
| Forward Hostname | `canvas-proxy` |
| Forward Port | `8000` |
| Block Common Exploits | on |
| Websockets Support | off |
| SSL | request a Let's Encrypt certificate, Force SSL on |

NPM must be on the `web` network too — it resolves `canvas-proxy` by container
name. Then set in `.env`, to match the domain exactly:

```
PROXY_BASE_URL=https://canvas-proxy.example.edu
DJANGO_ALLOWED_HOSTS=canvas-proxy.example.edu
CSRF_TRUSTED_ORIGINS=https://canvas-proxy.example.edu
```

`PROXY_BASE_URL` is what the proxy tells Canvas its redirect URI is, so it has
to match the developer keys exactly, https included.

### Check the developer keys

```bash
docker compose exec canvas-proxy python manage.py check_canvas_keys
```

Asks Canvas to start an authorization for each tier and reports what it says.
No user is involved and no flow is completed, so it is safe to run any time.
It distinguishes the two mistakes that look identical from the outside — a key
Canvas doesn't recognise, and a key whose Redirect URIs don't include this
proxy's callback.

### First staff account

```bash
docker compose exec canvas-proxy python manage.py createsuperuser
```

### Two failure modes worth recognising

- **Every form POST returns a bare 403.** Cookies are marked `Secure` but the
  app is being served over plain http. Either finish the TLS setup, or set
  `SECURE_COOKIES=0` and `SECURE_SSL_REDIRECT=0` while testing.
- **The browser bounces between http and https forever.** `SECURE_SSL_REDIRECT`
  is on with no TLS terminator in front, or NPM isn't sending
  `X-Forwarded-Proto`. Check `BEHIND_TLS_PROXY=1`.

### Verifying the image

```bash
./tools/e2e/run-docker.sh
```

Builds the image, brings up the whole stack under a separate compose project
against a stand-in Canvas, drives the full authorization chain over HTTP, and
tears itself down. It never touches your `.env` or a running deployment.

---

## Access tiers

A tier is one Canvas developer key plus the limits imposed on apps using it.
Canvas enforces the key's own scopes upstream; the tier's method and path rules
are a **second, proxy-side gate**, so one broadly-scoped key can still back a
narrow tier.

Defaults from `seed_tiers`:

| Tier | Methods | Reach |
|---|---|---|
| `read_basic` | `GET`, `HEAD` | own profile, courses, calendar, planner |
| `read_write` | all | course-level resources, groups, files; no account endpoints |
| `full` | all | everything the key allows, including GraphQL and acting-as |

Rules are editable per tier in the Django admin:

- **`allowed_methods`** — HTTP methods the tier may use. Empty means all.
- **`path_rules`** — allowlist of `{"methods": [...], "pattern": "regex"}`,
  matched against the upstream path. Empty means every path.
- **`denied_patterns`** — checked first, and always wins.
- **`allow_masquerade`** — whether `as_user_id=` may be used. Off by default;
  a Canvas admin key plus masquerade is full impersonation.

`/api/graphql` is denied on the two narrow tiers, since GraphQL would otherwise
route around the REST path rules entirely.

---

## Using the proxy (for app developers)

Sign in at `/`, register an app, wait for approval. Then:

**1. Send the user to authorize**

```
https://your-proxy-host/oauth2/auth
  ?client_id=<client_id>
  &response_type=code
  &redirect_uri=<exactly as registered>
  &state=<random>
```

Public clients (SPA, mobile, CLI) must also send `code_challenge` and
`code_challenge_method=S256`.

**2. Exchange the code**

```bash
curl -X POST https://your-proxy-host/oauth2/token \
  -d grant_type=authorization_code \
  -d client_id=... -d client_secret=... \
  -d redirect_uri=... -d code=...
```

Returns `access_token`, `refresh_token`, `expires_in`, and a `user` block
shaped like Canvas's own token response.

**3. Call the API**

```bash
curl https://your-proxy-host/api/v1/users/self/profile \
  -H "Authorization: Bearer <access_token>"
```

Every path under `/api/` maps to the same path on the Canvas host. Pagination
`Link` headers are rewritten to point back at the proxy, so cursoring works
unchanged. File-download redirects to presigned storage URLs pass through
untouched.

`/login/oauth2/auth` and `/login/oauth2/token` are accepted as aliases, so a
client written against Canvas directly can often be repointed by changing only
its base URL.

---

## Security properties

**Redirect URIs** are matched exactly — no wildcards, no prefix matching, no
trailing-slash forgiveness. Non-localhost URIs must be HTTPS. If the
`redirect_uri` doesn't match, the proxy renders an error page rather than
redirecting, so it can't be used as an open redirect.

**Approval is load-bearing.** Editing an approved app's redirect URIs, tier, or
client type puts it back in the review queue, because the approval no longer
describes the app that was approved.

**Codes and tokens.** Authorization codes are single-use and live 60 seconds.
Refresh tokens rotate on every use. Replaying either one is treated as evidence
of a leak: the whole Canvas grant is revoked, upstream as well as locally.

**At rest.** Canvas tokens and developer-key secrets are Fernet-encrypted.
Proxy-issued tokens are stored only as HMAC digests keyed by `SECRET_KEY`, so a
database dump yields no usable credential. Client secrets go through Django's
password hasher and are shown exactly once.

**In transit.** The app's bearer token is never forwarded upstream; the Canvas
token is never returned downstream. Cookies, `Authorization`, and
`X-Forwarded-*` headers from the caller are stripped before forwarding, and
`Set-Cookie` is stripped on the way back. An inline `?access_token=` parameter
is refused outright.

**Containment.** Suspending an app revokes every Canvas grant it holds. Disabling
a tier stops every app on it. Revoking the developer key in Canvas kills that
whole tier upstream, which is why the tiers exist as separate keys.

**Audit.** Every proxied call is recorded — app, Canvas user, method, path,
status, duration, and the denial reason if refused — visible in the admin, on
the app's own page, and to reviewers.

---

## Operations

Run daily from cron:

```bash
docker compose exec -T canvas-proxy python manage.py prune_expired
```

Deletes spent authorization state, long-dead tokens, and request logs past
`REQUEST_LOG_RETENTION_DAYS`. Dead refresh tokens are kept 7 days so replay
detection still has something to match.

Two things worth knowing:

- `RATE_LIMIT_PER_MINUTE` uses the Django cache. The default LocMemCache is
  per-process, so the effective limit multiplies by your worker count — point
  `CACHE_BACKEND` at Redis if you run more than one.
- `GET /oauth2/auth` writes a short-lived row before showing the consent screen,
  so an unauthenticated flood can grow that table between prunes. If that
  matters for your exposure, rate-limit the endpoint at the edge.

---

## Tests

```bash
.venv/bin/python manage.py test
```

141 tests, no network access — Canvas is mocked at the `canvasclient` boundary.
They cover the full authorization chain, tier enforcement, header and query
filtering, pagination rewriting, code/refresh replay handling, PKCE, the
approval workflow, and ownership boundaries on the dashboard.

There are also two end-to-end checks that run a stand-in Canvas and drive the
whole chain over HTTP against a throwaway database — one against a plain Django
server, one against the built container image:

```bash
./tools/e2e/run.sh          # source
./tools/e2e/run-docker.sh   # the image, with Postgres and Redis
```

It asserts the things unit tests can't quite reach — that the Canvas token never
appears in any response, that a raw Canvas token is rejected by the proxy, that
pagination links come back rewritten, and that revocation actually kills a live
token.

---

## Layout

```
config/        settings, root URLs
accounts/      custom user, Canvas sign-in for the dashboard
registry/      access tiers, app registration, staff review, seed commands
oauth/         authorize / callback / token / revoke, grant + token storage
gateway/       the proxy view, tier enforcement, rate limiting, audit log
canvasclient/  Canvas OAuth + REST wrapper, encryption helpers
templates/     dashboard, consent screen
tools/e2e/     fake Canvas + live-server integration checks
Dockerfile     gunicorn image, statics baked in at build
docker-compose.yml        app + Postgres + Redis, on the `web` network
docker-compose.smoke.yml  verification overlay, adds the stand-in Canvas
```
