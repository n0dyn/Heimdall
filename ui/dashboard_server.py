"""
Standalone dashboard server.

Serves the console only after a Heimdall operator session. The browser never
receives the operator API key. Agent traffic does not come through here.
"""

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

STATIC_SUFFIXES = (".svg", ".ico", ".png", ".css", ".js", ".map", ".woff", ".woff2", ".jpg", ".jpeg")

# The console is one inline document plus Chart.js and the two webfonts.
# Scripts from anywhere else stay blocked.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def upstream_base() -> str:
    return os.getenv(
        "HEIMDALL_INTERNAL_API",
        f"http://127.0.0.1:{os.getenv('SIEM_SERVER_PORT', '8010')}",
    ).rstrip("/")


def render_index(content: str) -> str:
    """Point the page at this server and do not embed the operator key."""
    injected = (
        "        window.API_CONFIG = {\n"
        "            api_url: '',\n"
        "            api_key: '',\n"
        "            proxy: true\n"
        "        };"
    )
    start = content.find("window.API_CONFIG = {")
    if start == -1:
        return content
    end = content.find("};", start)
    if end == -1:
        return content
    line_start = content.rfind("\n", 0, start) + 1
    return content[:line_start] + injected + content[end + 2:]


def trust_proxy() -> bool:
    return os.getenv("SIEM_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"}


def public_env() -> bool:
    return os.getenv("SIEM_PUBLIC", "").strip().lower() in {"1", "true", "yes"}


def _header(headers, name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    direct = getter(name) or ""
    if direct:
        return str(direct)
    target = name.lower()
    items = getattr(headers, "items", None)
    if items is None:
        return ""
    for key, value in items():
        if str(key).lower() == target and value:
            return str(value)
    return ""


def _valid_ip(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return ""
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return candidate


def proxy_client_ip(headers, peer: str) -> str:
    """Viewer address used to bind an operator session.

    CF-Connecting-IP is the address Cloudflare actually saw. The left-most
    X-Forwarded-For value is client-supplied, so a stolen cookie could replay
    it through the tunnel. The last address is the one the proxy appended.
    """
    if trust_proxy() and headers is not None:
        cloudflare = _valid_ip(_header(headers, "CF-Connecting-IP"))
        if cloudflare:
            return cloudflare
        parts = [part.strip() for part in _header(headers, "X-Forwarded-For").split(",") if part.strip()]
        for part in reversed(parts):
            parsed = _valid_ip(part)
            if parsed:
                return parsed
    return peer or ""


def anonymous_console_allowed(headers=None, enrolled: bool | None = None) -> bool:
    """Open console is only for a private LAN before the first enrollment.

    Public mode, a trusted proxy, or a Cloudflare tunnel header means this
    request is not that LAN. Do not serve the console or attach the operator key.
    """
    if trust_proxy() or public_env():
        return False
    if _header(headers, "CF-Connecting-IP"):
        return False
    if enrolled is None:
        enrolled = operator_enrolled()
    return not enrolled


_enrolled_cache = {"at": 0.0, "value": False}


def operator_enrolled() -> bool:
    """True only after an operator finishes enrollment.

    Until then the console stays on the server-side key. Enrollment has not
    happened on this hub, and a missing status answer must not lock it.
    """
    now = time.monotonic()
    if now - _enrolled_cache["at"] < 5:
        return _enrolled_cache["value"]
    value = False
    request = urllib.request.Request(upstream_base() + "/auth/status", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8") or "{}")
            value = bool(body.get("enrolled"))
    except Exception:
        value = False
    _enrolled_cache["at"] = now
    _enrolled_cache["value"] = value
    return value


def upstream_headers(incoming, client_ip: str) -> dict:
    """Headers for the API. The operator key stays on the API, not in this proxy.

    Forwarded proto and host are copied only when a reverse proxy is trusted.
    A browser that can reach this port directly must not be able to spoof them.
    """
    headers = {"X-Heimdall-Client-Ip": client_ip or ""}
    proto = "http"
    host = ""
    cookie = ""
    content_type = ""
    if incoming is not None:
        cookie = incoming.get("Cookie") or ""
        content_type = incoming.get("Content-Type") or ""
        if trust_proxy():
            proto = incoming.get("X-Forwarded-Proto") or "http"
            host = incoming.get("X-Forwarded-Host") or ""
        else:
            host = incoming.get("Host") or ""
    headers["X-Forwarded-Proto"] = proto
    if host:
        headers["X-Forwarded-Host"] = host
    if cookie:
        headers["Cookie"] = cookie
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def security_header_pairs() -> list[tuple[str, str]]:
    return [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
        ("Cache-Control", "no-store"),
    ]


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the console and proxy the API after the operator session is checked."""

    def end_headers(self):
        for key, value in security_header_pairs():
            self.send_header(key, value)
        super().end_headers()

    def _path_only(self) -> str:
        return (self.path or "/").split("?")[0]

    def _is_dashboard_page(self, path: str) -> bool:
        return path == "/" or path.startswith("/org/") or path.startswith("/index.html")

    def _is_login_page(self, path: str) -> bool:
        return path in {"/login", "/login.html"}

    def _is_static(self, path: str) -> bool:
        return path.endswith(STATIC_SUFFIXES)

    def _client_ip(self) -> str:
        peer = self.client_address[0] if self.client_address else ""
        return proxy_client_ip(self.headers, peer)

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        path = self._path_only()
        if self._is_static(path):
            self._serve_file(path)
            return
        if self._is_login_page(path):
            self._serve_login()
            return
        if self._is_dashboard_page(path):
            if self._session_state() == "full" or anonymous_console_allowed(self.headers):
                self._serve_index()
            else:
                self._serve_login()
            return
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def _session_state(self) -> str:
        """Return full, limited, or none. Fail closed when the API cannot be asked."""
        cookie = self.headers.get("Cookie") or ""
        if "heimdall_session=" not in cookie:
            return "none"
        headers = upstream_headers(self.headers, self._client_ip())
        request = urllib.request.Request(
            upstream_base() + "/auth/session",
            headers=headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status != 200:
                    return "none"
                body = json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError:
            return "none"
        except Exception:
            return "none"
        if body.get("limited"):
            return "limited"
        if body.get("ok"):
            return "full"
        return "none"

    def _serve_index(self):
        try:
            content = Path("index.html").read_text(encoding="utf-8")
            content = render_index(content)
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def _serve_login(self):
        file_path = Path("login.html")
        if not file_path.is_file():
            self.send_response(404)
            self.end_headers()
            return
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, path: str):
        rel = path.lstrip("/")
        file_path = Path(rel)
        if not file_path.is_file() or ".." in file_path.parts:
            self.send_response(404)
            self.end_headers()
            return
        data = file_path.read_bytes()
        self.send_response(200)
        if path.endswith(".svg"):
            ctype = "image/svg+xml"
        elif path.endswith(".ico"):
            ctype = "image/x-icon"
        elif path.endswith(".css"):
            ctype = "text/css"
        elif path.endswith(".js"):
            ctype = "text/javascript"
        else:
            ctype = "application/octet-stream"
        self.send_header("Content-type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        url = upstream_base() + self.path
        headers = upstream_headers(self.headers, self._client_ip())
        if anonymous_console_allowed(self.headers):
            api_key = os.getenv("SIEM_API_KEY", "")
            if api_key:
                headers["api-key"] = api_key
        request = urllib.request.Request(url, data=body, headers=headers, method=self.command)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read()
                status = response.status
                upstream_headers_out = response.headers
                ctype = upstream_headers_out.get("Content-Type", "application/json")
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            status = exc.code
            upstream_headers_out = exc.headers
            ctype = exc.headers.get("Content-Type", "application/json") if exc.headers else "application/json"
        except Exception as exc:
            payload = str(exc).encode("utf-8")
            status = 502
            upstream_headers_out = None
            ctype = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if upstream_headers_out is not None:
            setter = getattr(upstream_headers_out, "get_all", None)
            cookies = setter("Set-Cookie") if setter else []
            for cookie in cookies or []:
                self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    port = int(os.getenv("DASHBOARD_PORT", "8501"))
    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    print(f"Dashboard server running on port {port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown requested")
        server.shutdown()


if __name__ == "__main__":
    main()
