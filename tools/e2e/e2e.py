"""Drive the proxy end to end over real HTTP against the fake Canvas.

    python tools/e2e/e2e.py <client_id> <client_secret>

Environment:
  PROXY_URL        where to reach the proxy      (default http://127.0.0.1:8099)
  CANVAS_URL       the Canvas origin the proxy is configured with
  CANVAS_FROM_HOST where *this script* should dial that origin instead. Needed
                   when the proxy runs in a container and knows Canvas by a
                   name only resolvable inside Docker.
"""

import os
import re
import sys
from urllib.parse import parse_qs, urlencode, urlsplit

import requests

PROXY = os.environ.get("PROXY_URL", "http://127.0.0.1:8099")
CANVAS = os.environ.get("CANVAS_URL", "http://127.0.0.1:9911")
CANVAS_FROM_HOST = os.environ.get("CANVAS_FROM_HOST", CANVAS)
REDIRECT = "http://localhost:3000/callback"

CLIENT_ID = sys.argv[1]
CLIENT_SECRET = sys.argv[2]

passed, failed = [], []


def check(label, condition, detail=""):
    (passed if condition else failed).append(label)
    mark = "ok  " if condition else "FAIL"
    print(f"  [{mark}] {label}{'  -> ' + str(detail) if detail and not condition else ''}")


def dialable(url):
    """Rewrite a Canvas URL to an address reachable from this machine."""
    if CANVAS_FROM_HOST != CANVAS and url.startswith(CANVAS):
        return CANVAS_FROM_HOST + url[len(CANVAS) :]
    return url


session = requests.Session()

print("\n1. authorize -> consent screen")
auth_url = f"{PROXY}/oauth2/auth?" + urlencode({
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT,
    "response_type": "code",
    "state": "app-state-xyz",
})
r = session.get(auth_url)
check("consent page renders", r.status_code == 200, r.status_code)
check("consent names the app", "Gradebook Sync" in r.text)
check("consent names the tier", "Read-only" in r.text)

csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text).group(1)
action = re.search(r'action="(/oauth2/auth/[^"]+/confirm)"', r.text).group(1)

print("\n2. consent -> canvas -> callback -> app redirect")
r = session.post(
    PROXY + action,
    data={"csrfmiddlewaretoken": csrf, "decision": "allow"},
    headers={"Referer": auth_url},
    allow_redirects=False,
)
check("redirects to Canvas", r.headers.get("Location", "").startswith(CANVAS), r.headers.get("Location"))
check("app state not leaked to Canvas", "app-state-xyz" not in r.headers.get("Location", ""))

r = session.get(dialable(r.headers["Location"]), allow_redirects=False)   # fake Canvas
r = session.get(r.headers["Location"], allow_redirects=False)          # proxy callback
location = r.headers.get("Location", "")
check("returns to the app's redirect_uri", location.startswith(REDIRECT), location)
query = parse_qs(urlsplit(location).query)
check("state round-trips", query.get("state") == ["app-state-xyz"], query.get("state"))
check("an authorization code is returned", "code" in query)
code = query["code"][0]

print("\n3. token exchange")
r = requests.post(f"{PROXY}/oauth2/token", data={
    "grant_type": "authorization_code",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "redirect_uri": REDIRECT,
    "code": code,
})
check("exchange succeeds", r.status_code == 200, r.text[:200])
body = r.json()
token = body["access_token"]
check("Canvas token is not disclosed", "CANVAS-ACCESS-TOKEN-SECRET" not in r.text)
check("Canvas refresh token is not disclosed", "CANVAS-REFRESH-TOKEN-SECRET" not in r.text)
check("user block mirrors Canvas", body.get("user", {}).get("id") == 4321, body.get("user"))
check("no-store on the token response", r.headers.get("Cache-Control") == "no-store")

print("\n4. reusing the code")
r2 = requests.post(f"{PROXY}/oauth2/token", data={
    "grant_type": "authorization_code", "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT, "code": code,
})
check("replayed code is refused", r2.status_code == 400, r2.status_code)

print("\n   (grant was revoked by the replay; re-authorizing)")
session2 = requests.Session()
r = session2.get(auth_url)
csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text).group(1)
action = re.search(r'action="(/oauth2/auth/[^"]+/confirm)"', r.text).group(1)
r = session2.post(PROXY + action, data={"csrfmiddlewaretoken": csrf, "decision": "allow"},
                  headers={"Referer": auth_url}, allow_redirects=False)
r = session2.get(dialable(r.headers["Location"]), allow_redirects=False)
r = session2.get(r.headers["Location"], allow_redirects=False)
code = parse_qs(urlsplit(r.headers["Location"]).query)["code"][0]
body = requests.post(f"{PROXY}/oauth2/token", data={
    "grant_type": "authorization_code", "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT, "code": code,
}).json()
token, refresh = body["access_token"], body["refresh_token"]

print("\n5. proxied API call")
r = requests.get(f"{PROXY}/api/v1/courses", headers={"Authorization": f"Bearer {token}"})
check("call succeeds", r.status_code == 200, r.text[:200])
check("Canvas payload comes through", r.json()[0]["name"] == "Intro to Proxies")
check("pagination rewritten to the proxy", PROXY in r.headers.get("Link", ""), r.headers.get("Link"))
check("Canvas host absent from Link", CANVAS not in r.headers.get("Link", ""))
check("rate-limit header passed through", r.headers.get("X-Rate-Limit-Remaining") == "699.1")
check("upstream Set-Cookie stripped", "Set-Cookie" not in r.headers)

print("\n6. tier enforcement")
r = requests.post(f"{PROXY}/api/v1/courses", headers={"Authorization": f"Bearer {token}"})
check("write refused on read-only tier", r.status_code == 403, r.status_code)
r = requests.get(f"{PROXY}/api/v1/accounts/1/users", headers={"Authorization": f"Bearer {token}"})
check("account endpoint refused", r.status_code == 403, r.status_code)
r = requests.get(f"{PROXY}/api/v1/courses?as_user_id=99", headers={"Authorization": f"Bearer {token}"})
check("masquerade refused", r.status_code == 403, r.status_code)
r = requests.get(f"{PROXY}/api/v1/courses", headers={"Authorization": "Bearer made-up"})
check("bogus token refused", r.status_code == 401, r.status_code)
r = requests.get(f"{PROXY}/api/v1/courses")
check("missing token refused", r.status_code == 401, r.status_code)

print("\n7. the Canvas token cannot be used against the proxy directly")
r = requests.get(f"{PROXY}/api/v1/courses",
                 headers={"Authorization": "Bearer CANVAS-ACCESS-TOKEN-SECRET"})
check("raw Canvas token rejected by the proxy", r.status_code == 401, r.status_code)

print("\n8. refresh rotation")
r = requests.post(f"{PROXY}/oauth2/token", data={
    "grant_type": "refresh_token", "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET, "refresh_token": refresh,
})
check("refresh succeeds", r.status_code == 200, r.text[:200])
new = r.json()
check("a new access token is issued", new["access_token"] != token)
check("the refresh token rotated", new["refresh_token"] != refresh)
r = requests.get(f"{PROXY}/api/v1/courses", headers={"Authorization": f"Bearer {new['access_token']}"})
check("the new token works", r.status_code == 200, r.status_code)

print("\n9. revocation")
r = requests.post(f"{PROXY}/oauth2/revoke", data={"token": new["access_token"]})
check("revoke accepted", r.status_code == 200, r.status_code)
r = requests.get(f"{PROXY}/api/v1/courses", headers={"Authorization": f"Bearer {new['access_token']}"})
check("revoked token is dead", r.status_code == 401, r.status_code)

print("\n10. metadata")
r = requests.get(f"{PROXY}/.well-known/oauth-authorization-server")
check("metadata served", r.status_code == 200 and r.json()["token_endpoint"].endswith("/oauth2/token"))

print(f"\n{'=' * 52}\n{len(passed)} passed, {len(failed)} failed")
if failed:
    for name in failed:
        print(f"  FAILED: {name}")
    sys.exit(1)
