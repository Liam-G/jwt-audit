"""Deliberately vulnerable local JWT fixture for authorized testing only."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt

HOST = "127.0.0.1"
PORT = 8765
DEMO_SECRET = "change-me"  # noqa: S105 - intentionally weak local fixture


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if self.path != "/api/me":
            self._json(404, {"error": "not found"})
            return
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            self._json(401, {"error": "authentication required"})
            return
        try:
            claims = jwt.decode(
                authorization.removeprefix("Bearer "),
                DEMO_SECRET,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
        except jwt.PyJWTError:
            self._json(401, {"error": "invalid token"})
            return
        self._json(200, {"accepted": True, "claims": claims})

    def _json(self, status: int, body: dict[str, object]) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, message: str, *args: object) -> None:
        return


if __name__ == "__main__":
    print(f"Deliberately vulnerable demo listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
