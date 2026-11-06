"""Single-operator sign-in for an internet-exposed Heimdall.

Humans get a server session only after two factors:
a passkey (WebAuthn, user verification required) plus an authenticator code,
or, when the browser has no passkey origin, a server-generated login secret
plus an authenticator code.

Agent API keys never become that session. The operator env key works only
from loopback, so a copied key cannot open the API from the internet.
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import ipaddress
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

COOKIE_SESSION = "heimdall_session"
COOKIE_PENDING = "heimdall_pending"
COOKIE_SETUP = "heimdall_setup"
COOKIE_CHALLENGE = "heimdall_challenge"

IDLE = timedelta(minutes=30)
ABSOLUTE = timedelta(hours=8)
PENDING_TTL = timedelta(minutes=5)
SETUP_TTL = timedelta(minutes=15)
LOCK_WINDOW_SECONDS = 15 * 60
LOGIN_FAIL_LIMIT = 8
SETUP_FAIL_LIMIT = 5
API_KEY_FAIL_LIMIT = 30

# Set by raw ASGI middleware so the value stays visible inside the endpoint.
_scope_var: contextvars.ContextVar = contextvars.ContextVar("heimdall_scope", default=None)


def public_mode() -> bool:
    return os.getenv("SIEM_PUBLIC", "").strip().lower() in {"1", "true", "yes"}


def assert_public_config(api_key: str) -> None:
    """Refuse a public boot that still has the published default key or cleartext origin."""
    if (api_key or "") == "default-insecure-key-change-me":
        print("WARNING: SIEM_API_KEY is still the default. Change it before this host is reachable.")
        if public_mode():
            raise RuntimeError("SIEM_PUBLIC=1 refuses the default SIEM_API_KEY")
    if not public_mode():
        return
    origin = os.getenv("SIEM_ORIGIN", "").strip()
    if not origin.startswith("https://"):
        raise RuntimeError("SIEM_PUBLIC=1 requires SIEM_ORIGIN=https://your-domain")
    print("Heimdall public mode is on. Publish only 443. Leave 8010 and UDP 5514 off the internet.")


def data_dir() -> Path:
    raw = os.getenv("SIEM_DATA_DIR", "").strip()
    if raw:
        return Path(raw)
    app_data = Path("/app/data")
    if app_data.is_dir():
        return app_data
    return Path("data")


def bootstrap_path() -> Path:
    return data_dir() / "bootstrap.token"


def auth_key() -> bytes:
    """Key that encrypts the authenticator secret. Stays on disk, mode 600."""
    path = data_dir() / "auth_secret"
    if path.is_file():
        raw = path.read_text(encoding="utf-8").strip()
        if raw:
            return base64.b64decode(raw)
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(key).decode("ascii") + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def read_bootstrap() -> str:
    env = os.getenv("SIEM_BOOTSTRAP_TOKEN", "").strip()
    if env:
        return env
    path = bootstrap_path()
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return ""


def ensure_operator_bootstrap(enrolled: bool) -> None:
    if enrolled:
        return
    if os.getenv("SIEM_BOOTSTRAP_TOKEN", "").strip():
        print("Operator enrollment uses SIEM_BOOTSTRAP_TOKEN from the environment.")
        return
    path = bootstrap_path()
    if path.is_file() and path.read_text(encoding="utf-8").strip():
        print(f"Operator enrollment token is in {path}")
        return
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"Operator enrollment token written to {path}")


def delete_bootstrap_file() -> None:
    try:
        bootstrap_path().unlink(missing_ok=True)
    except OSError:
        pass


def tokens_equal(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_login_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + derived.hex()


def verify_login_secret(secret: str, stored: str) -> bool:
    try:
        kind, salt_hex, digest_hex = stored.split("$", 2)
        if kind != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        derived = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(derived, expected)
    except (ValueError, TypeError):
        return False


def _keystream(key: bytes, nonce: bytes, size: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < size:
        out += hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:size]


def encrypt_text(plain: str) -> str:
    key = auth_key()
    nonce = secrets.token_bytes(16)
    raw = plain.encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(raw, _keystream(key, nonce, len(raw))))
    mac = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(nonce + mac + ct).decode("ascii")


def decrypt_text(blob: str) -> str:
    key = auth_key()
    raw = base64.b64decode(blob)
    nonce, mac, ct = raw[:16], raw[16:48], raw[48:]
    expected = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("authenticator secret failed its integrity check")
    plain = bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))
    return plain.decode("utf-8")


def new_totp():
    import pyotp
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="operator", issuer_name="Heimdall")
    return secret, uri


def verify_totp(secret: str, code: str) -> bool:
    import pyotp
    digits = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(digits) != 6:
        return False
    return bool(pyotp.TOTP(secret).verify(digits, valid_window=1))


def new_recovery_codes() -> tuple[list[str], list[str]]:
    plain = []
    hashes = []
    for _ in range(10):
        raw = secrets.token_hex(6).upper()
        code = f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}"
        plain.append(code)
        hashes.append(hash_recovery(code))
    return plain, hashes


def hash_recovery(code: str) -> str:
    normalized = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    return hmac.new(auth_key(), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def new_login_secret() -> str:
    return "heimdall-" + secrets.token_urlsafe(32)


def request_origin(request: Request) -> str:
    configured = os.getenv("SIEM_ORIGIN", "").strip().rstrip("/")
    if configured:
        return configured
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    return f"{proto}://{host}"


def request_rp_id(request: Request) -> str:
    configured = os.getenv("SIEM_RP_ID", "").strip()
    if configured:
        return configured
    return urlparse(request_origin(request)).hostname or ""


def webauthn_available(origin: str, rp_id: str) -> bool:
    if not rp_id or not origin:
        return False
    try:
        ipaddress.ip_address(rp_id)
        return False
    except ValueError:
        pass
    if origin.startswith("https://"):
        return True
    host = urlparse(origin).hostname or ""
    return host in {"localhost", "127.0.0.1"}


def cookie_secure(request: Request) -> bool:
    if os.getenv("SIEM_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes"}:
        return True
    if public_mode():
        return True
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return proto == "https"


def https_ok(request: Request) -> bool:
    if not public_mode():
        return True
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return proto == "https"


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client and request.client.host else ""
    if peer in {"127.0.0.1", "::1", "localhost"}:
        forwarded = (request.headers.get("x-heimdall-client-ip") or "").strip()
        if forwarded:
            try:
                ipaddress.ip_address(forwarded)
                return forwarded
            except ValueError:
                pass
    return peer or "unknown"


def operator_key_allowed(request: Request | None) -> bool:
    """The env operator key is a local admin secret, not an internet credential."""
    if request is None or request.client is None:
        return False
    return (request.client.host or "") in {"127.0.0.1", "::1", "localhost", "testclient"}


def network_operator_write(request: Request | None) -> bool:
    """Check-in calls may still use the operator key from the agent host.

    Reads and console changes stay on loopback or a signed-in session.
    """
    if request is None:
        return False
    return (request.method.upper(), request.url.path) in _AGENT_WRITES


_AGENT_WRITES = {
    ("POST", "/ingest"),
    ("POST", "/heartbeat"),
    ("POST", "/system-status"),
    ("POST", "/metrics/samples"),
}


def agent_read_blocked(request: Request | None) -> bool:
    if request is None or not public_mode():
        return False
    return (request.method.upper(), request.url.path) not in _AGENT_WRITES


def current_request() -> Request | None:
    scope = _scope_var.get()
    if not scope:
        return None
    return Request(scope)


def set_auth_cookie(response, name: str, value: str, max_age: int, request: Request) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        secure=cookie_secure(request),
        samesite="strict",
        path="/",
    )


def clear_auth_cookie(response, name: str, request: Request) -> None:
    response.delete_cookie(
        name,
        path="/",
        samesite="strict",
        secure=cookie_secure(request),
        httponly=True,
    )


def as_utc(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class RequestScopeMiddleware:
    """Bind the ASGI scope for the operator gate. Not BaseHTTPMiddleware.

    BaseHTTPMiddleware runs the endpoint in another task and drops context.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = _scope_var.set(scope)

        async def send_locked(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {key.lower() for key, _ in headers}
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
                for key, value in extra:
                    if key not in present:
                        headers.append((key, value))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_locked)
        finally:
            _scope_var.reset(token)
