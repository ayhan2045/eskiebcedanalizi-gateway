import os
import hmac
import hashlib
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

GATEWAY_PASSWORD = os.environ.get("GATEWAY_PASSWORD", "")
GATEWAY_SECRET = os.environ.get("GATEWAY_SECRET", "")

def _sign(value: str) -> str:
    return hmac.new(GATEWAY_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()

def _parse_cookies(cookie_header: str) -> dict:
    cookies = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        cookies[k.strip()] = v.strip()
    return cookies

def _is_authed(headers) -> bool:
    cookie = headers.get("Cookie", "")
    if not cookie:
        return False
    cookies = _parse_cookies(cookie)
    token = cookies.get("gw_token", "")
    sig = cookies.get("gw_sig", "")
    if not token or not sig:
        return False
    expected = _sign(token)
    return hmac.compare_digest(expected, sig)

LOGIN_HTML = """<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Giriş</title>
  <style>
    body{font-family:Arial, sans-serif;background:#0b0b0b;color:#fff;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
    .box{width:min(420px,92vw);background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:18px}
    h1{font-size:18px;margin:0 0 12px}
    input{width:100%;padding:12px;border-radius:10px;border:1px solid #444;background:#111;color:#fff;box-sizing:border-box}
    button{margin-top:12px;width:100%;padding:12px;border-radius:10px;border:0;background:#2d6cdf;color:#fff;font-weight:700;cursor:pointer}
    .err{margin-top:10px;color:#ff7b7b;font-size:13px}
  </style>
</head>
<body>
  <div class="box">
    <h1>Oturum aç</h1>
    <form method="POST" action="/__auth/login">
      <input type="password" name="password" placeholder="Şifre" autofocus />
      <input type="hidden" name="next" value="{NEXT}" />
      <button type="submit">Giriş</button>
      {ERROR}
    </form>
  </div>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/__auth/check":
            if _is_authed(self.headers):
                self.send_response(200)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            return

        if path == "/__auth/logout":
            headers = [
                ("Set-Cookie", "gw_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "gw_sig=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
                ("Location", "/__auth/login"),
            ]
            self.send_response(302)
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            return

        if path == "/__auth/login":
            next_url = qs.get("next", ["/"])[0]
            err = qs.get("err", [""])[0]
            safe_next = next_url if next_url.startswith("/") else "/"
            error_html = '<div class="err">Şifre hatalı.</div>' if err == "1" else ""
            html = LOGIN_HTML.replace("{NEXT}", safe_next).replace("{ERROR}", error_html)
            self._send(200, html)
            return

        self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/__auth/login":
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        data = self.rfile.read(length).decode("utf-8")
        form = urllib.parse.parse_qs(data)

        password = (form.get("password", [""])[0] or "").strip()
        next_url = form.get("next", ["/"])[0]
        safe_next = next_url if next_url.startswith("/") else "/"

        if not GATEWAY_PASSWORD or not GATEWAY_SECRET:
            self._send(500, "Missing env vars", "text/plain; charset=utf-8")
            return

        if password != GATEWAY_PASSWORD:
            loc = "/__auth/login?err=1&next=" + urllib.parse.quote(safe_next)
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        token = "ok"
        sig = _sign(token)
        cookie_common = "Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"
        self.send_response(302)
        self.send_header("Set-Cookie", f"gw_token={token}; {cookie_common}")
        self.send_header("Set-Cookie", f"gw_sig={sig}; {cookie_common}")
        self.send_header("Location", safe_next)
        self.end_headers()

def main():
    port = int(os.environ.get("AUTH_PORT", "9000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
