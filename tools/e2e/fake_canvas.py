"""A stand-in Canvas instance, just enough to drive the proxy end to end."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

PORT = 9911
ISSUED = {"access": "CANVAS-ACCESS-TOKEN-SECRET", "refresh": "CANVAS-REFRESH-TOKEN-SECRET"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)

        if parts.path == "/login/oauth2/auth":
            # A real Canvas would show a login + consent page here.
            target = query["redirect_uri"][0]
            params = {"code": "CANVAS-AUTH-CODE", "state": query["state"][0]}
            self.send_response(302)
            self.send_header("Location", f"{target}?{urlencode(params)}")
            self.end_headers()
            return

        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {ISSUED['access']}":
            self._json(401, {"errors": [{"message": "Invalid access token."}]})
            return

        if parts.path == "/api/v1/courses":
            link = (
                f'<http://127.0.0.1:{PORT}/api/v1/courses?page=2>; rel="next", '
                f'<http://127.0.0.1:{PORT}/api/v1/courses?page=4>; rel="last"'
            )
            self._json(
                200,
                [{"id": 1, "name": "Intro to Proxies"}, {"id": 2, "name": "OAuth 201"}],
                {"Link": link, "X-Rate-Limit-Remaining": "699.1",
                 "Set-Cookie": "canvas_session=leaky; Path=/"},
            )
            return

        if parts.path == "/api/v1/users/self/profile":
            self._json(200, {"id": 4321, "name": "Ada Lovelace", "login_id": "ada"})
            return

        if parts.path == "/api/v1/accounts/1/users":
            self._json(200, [{"id": 1, "name": "should never be reached"}])
            return

        self._json(404, {"errors": [{"message": "not found"}]})

    def do_POST(self):
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = parse_qs(self.rfile.read(length).decode()) if length else {}

        if parts.path == "/login/oauth2/token":
            grant_type = body.get("grant_type", [""])[0]
            if body.get("client_secret", [""])[0] != "canvas-key-secret":
                self._json(401, {"error": "invalid_client"})
                return
            if grant_type == "authorization_code":
                self._json(200, {
                    "access_token": ISSUED["access"],
                    "refresh_token": ISSUED["refresh"],
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "user": {"id": 4321, "name": "Ada Lovelace",
                             "global_id": "10000000004321"},
                })
                return
            if grant_type == "refresh_token":
                self._json(200, {"access_token": ISSUED["access"], "expires_in": 3600})
                return
            self._json(400, {"error": "unsupported_grant_type"})
            return

        self._json(404, {"errors": [{"message": "not found"}]})

    def do_DELETE(self):
        self._json(200, {})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
