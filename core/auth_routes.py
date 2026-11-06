"""HTTP ceremonies for the single Heimdall operator."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import auth_store
from .operator_auth import (
    ABSOLUTE,
    API_KEY_FAIL_LIMIT,
    COOKIE_CHALLENGE,
    COOKIE_PENDING,
    COOKIE_SESSION,
    COOKIE_SETUP,
    IDLE,
    LOGIN_FAIL_LIMIT,
    LOCK_WINDOW_SECONDS,
    PENDING_TTL,
    SETUP_FAIL_LIMIT,
    SETUP_TTL,
    clear_auth_cookie,
    client_ip,
    current_request,
    decrypt_text,
    delete_bootstrap_file,
    encrypt_text,
    hash_login_secret,
    hash_recovery,
    hash_token,
    https_ok,
    new_login_secret,
    new_recovery_codes,
    new_totp,
    read_bootstrap,
    request_origin,
    request_rp_id,
    set_auth_cookie,
    tokens_equal,
    verify_login_secret,
    verify_totp,
    webauthn_available,
)

router = APIRouter(prefix="/auth", tags=["Operator"])


class BootstrapIn(BaseModel):
    bootstrap_token: str = ""


class SecretIn(BaseModel):
    secret: str = ""


class CodeIn(BaseModel):
    code: str = ""


class CredentialIn(BaseModel):
    credential: dict


def _store():
    return auth_store.get_store()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ip(request: Request) -> str:
    return client_ip(request)


def _audit(request: Request, action: str, detail: str) -> None:
    try:
        _store().audit(_ip(request), action, detail)
    except Exception:
        pass


def _locked(request: Request, action: str, limit: int) -> None:
    try:
        count = _store().failure_count(_ip(request), action, LOCK_WINDOW_SECONDS)
    except Exception:
        count = 0
    if count >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts. Wait 15 minutes.")


def _fail(request: Request, action: str, detail: str) -> None:
    try:
        _store().record_attempt(_ip(request), action, False)
    except Exception:
        pass
    _audit(request, action + "-fail", detail)


def _succeed(request: Request, action: str) -> None:
    try:
        _store().clear_failures(_ip(request), action)
        _store().record_attempt(_ip(request), action, True)
    except Exception:
        pass


def _require_https(request: Request) -> None:
    if not https_ok(request):
        raise HTTPException(status_code=400, detail="Public mode requires HTTPS.")


def _enrolled() -> bool:
    return _store().get_secret("enrolled") == "1"


def _has_passkey() -> bool:
    return len(_store().list_passkeys()) > 0


def _user_agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "")[:200]


def _session_row(request: Request):
    token = request.cookies.get(COOKIE_SESSION)
    if not token:
        return None
    row = _store().get_session(hash_token(token))
    if not row:
        return None
    now = _now()
    expires = row["expires_at"]
    seen = row["last_seen"]
    from .operator_auth import as_utc
    expires = as_utc(expires)
    seen = as_utc(seen)
    if expires <= now or seen + IDLE <= now:
        _store().delete_session(row["token_hash"])
        return None
    if (row.get("client_ip") or "") != _ip(request):
        _store().delete_session(row["token_hash"])
        _audit(request, "session-ip-mismatch", "session destroyed")
        return None
    row["expires_at"] = expires
    row["last_seen"] = seen
    return row


def identity_from_session(request: Request):
    """Operator identity for a full session, a limited marker, or None."""
    try:
        row = _session_row(request)
    except Exception:
        return None
    if not row:
        return None
    try:
        _store().touch_session(row["token_hash"], _now())
    except Exception:
        return None
    if row.get("limited"):
        return {"limited": True, "token_hash": row["token_hash"], "flags": row.get("flags") or ""}
    return {
        "role": "operator",
        "client_id": None,
        "site_id": None,
        "label": "session",
        "via": "session",
    }


def note_api_key_failure(request: Request | None) -> None:
    if request is None:
        return
    try:
        _store().record_attempt(_ip(request), "api_key", False)
    except Exception:
        pass


def api_key_locked(request: Request | None) -> bool:
    if request is None:
        return False
    try:
        return _store().failure_count(_ip(request), "api_key", LOCK_WINDOW_SECONDS) >= API_KEY_FAIL_LIMIT
    except Exception:
        return False


def _require_setup(request: Request) -> dict:
    token = request.cookies.get(COOKIE_SETUP)
    if not token:
        raise HTTPException(status_code=401, detail="Enrollment has not started.")
    row = _store().pop_challenge(hash_token(token))
    if not row or row.get("kind") != "setup":
        raise HTTPException(status_code=401, detail="Enrollment has expired. Start again.")
    # pop removed it; put it back so the next step still works. Callers that finish delete it.
    payload = row.get("payload") or "{}"
    _store().put_challenge(row["id"], "setup", row.get("challenge") or "", payload, row["expires_at"])
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        data = {}
    data["_id"] = row["id"]
    data["_expires"] = row["expires_at"]
    return data


def _save_setup(data: dict) -> None:
    row_id = data.pop("_id")
    expires = data.pop("_expires")
    _store().put_challenge(row_id, "setup", "", json.dumps(data), expires)


def _require_pending(request: Request) -> dict:
    token = request.cookies.get(COOKIE_PENDING)
    if not token:
        raise HTTPException(status_code=401, detail="Sign in again. The first factor expired.")
    row = _store().get_session(hash_token(token))
    # Pending login is stored as a short session with flags 'pending'.
    if not row or "pending" not in (row.get("flags") or ""):
        raise HTTPException(status_code=401, detail="Sign in again. The first factor expired.")
    from .operator_auth import as_utc
    if as_utc(row["expires_at"]) <= _now() or (row.get("client_ip") or "") != _ip(request):
        _store().delete_session(row["token_hash"])
        raise HTTPException(status_code=401, detail="Sign in again. The first factor expired.")
    return row


def _issue_pending(response, request: Request, factor: str) -> None:
    token = secrets.token_urlsafe(32)
    now = _now()
    _store().put_session({
        "token_hash": hash_token(token),
        "created_at": now,
        "last_seen": now,
        "expires_at": now + PENDING_TTL,
        "client_ip": _ip(request),
        "user_agent": _user_agent(request),
        "limited": True,
        "flags": "pending," + factor,
    })
    set_auth_cookie(response, COOKIE_PENDING, token, int(PENDING_TTL.total_seconds()), request)


def _issue_session(response, request: Request, limited: bool, flags: str = "") -> str:
    # A new sign-in kills every older session, including one copied off the machine.
    try:
        _store().delete_all_sessions()
    except Exception:
        pass
    token = secrets.token_urlsafe(32)
    now = _now()
    _store().put_session({
        "token_hash": hash_token(token),
        "created_at": now,
        "last_seen": now,
        "expires_at": now + ABSOLUTE,
        "client_ip": _ip(request),
        "user_agent": _user_agent(request),
        "limited": limited,
        "flags": flags,
    })
    set_auth_cookie(response, COOKIE_SESSION, token, int(ABSOLUTE.total_seconds()), request)
    return token


def _full_session(request: Request) -> dict:
    row = _session_row(request)
    if not row or row.get("limited"):
        raise HTTPException(status_code=401, detail="Sign in required.")
    _store().touch_session(row["token_hash"], _now())
    return row


def _limited_or_full(request: Request) -> dict:
    row = _session_row(request)
    if not row:
        raise HTTPException(status_code=401, detail="Sign in required.")
    _store().touch_session(row["token_hash"], _now())
    return row


@router.get("/status")
def auth_status(request: Request):
    origin = request_origin(request)
    rp_id = request_rp_id(request)
    try:
        enrolled = _enrolled()
        passkeys = _has_passkey()
    except Exception:
        enrolled = False
        passkeys = False
    return {
        "enrolled": enrolled,
        "passkey": passkeys,
        "webauthn": webauthn_available(origin, rp_id),
        "https": (request.headers.get("x-forwarded-proto") or request.url.scheme) == "https",
        "origin": origin,
    }


@router.get("/session")
def auth_session(request: Request):
    row = _session_row(request)
    if not row:
        raise HTTPException(status_code=401, detail="Sign in required.")
    if "pending" in (row.get("flags") or ""):
        raise HTTPException(status_code=401, detail="Sign in required.")
    _store().touch_session(row["token_hash"], _now())
    return {"ok": True, "limited": bool(row.get("limited"))}


@router.post("/logout")
def logout(request: Request):
    token = request.cookies.get(COOKIE_SESSION)
    if token:
        try:
            _store().delete_session(hash_token(token))
        except Exception:
            pass
    pending = request.cookies.get(COOKIE_PENDING)
    if pending:
        try:
            _store().delete_session(hash_token(pending))
        except Exception:
            pass
    response = JSONResponse({"ok": True})
    clear_auth_cookie(response, COOKIE_SESSION, request)
    clear_auth_cookie(response, COOKIE_PENDING, request)
    clear_auth_cookie(response, COOKIE_SETUP, request)
    _audit(request, "logout", "signed out")
    return response


@router.post("/setup/begin")
def setup_begin(body: BootstrapIn, request: Request):
    _require_https(request)
    _locked(request, "setup", SETUP_FAIL_LIMIT)
    if _enrolled():
        raise HTTPException(status_code=409, detail="An operator is already enrolled.")
    if not tokens_equal(body.bootstrap_token.strip(), read_bootstrap()):
        _fail(request, "setup", "bad enrollment token")
        raise HTTPException(status_code=401, detail="Enrollment token rejected.")
    _succeed(request, "setup")
    token = secrets.token_urlsafe(32)
    _store().put_challenge(
        hash_token(token),
        "setup",
        "",
        json.dumps({"secret_set": False, "passkey_set": False}),
        _now() + SETUP_TTL,
    )
    response = JSONResponse({
        "ok": True,
        "webauthn": webauthn_available(request_origin(request), request_rp_id(request)),
    })
    set_auth_cookie(response, COOKIE_SETUP, token, int(SETUP_TTL.total_seconds()), request)
    _audit(request, "setup-begin", "enrollment started")
    return response


@router.post("/setup/secret")
def setup_secret(request: Request):
    _require_https(request)
    if _enrolled():
        raise HTTPException(status_code=409, detail="An operator is already enrolled.")
    data = _require_setup(request)
    if webauthn_available(request_origin(request), request_rp_id(request)):
        raise HTTPException(status_code=400, detail="This origin supports passkeys. Create a passkey instead.")
    secret = new_login_secret()
    _store().put_secret("login_hash", hash_login_secret(secret))
    data["secret_set"] = True
    _save_setup(data)
    _audit(request, "setup-secret", "login secret created")
    return {"ok": True, "login_secret": secret}


@router.post("/setup/passkey/options")
def setup_passkey_options(request: Request):
    return _passkey_options(request, setup=True)


@router.post("/setup/passkey/finish")
def setup_passkey_finish(body: CredentialIn, request: Request):
    _require_https(request)
    if _enrolled():
        raise HTTPException(status_code=409, detail="An operator is already enrolled.")
    data = _require_setup(request)
    _finish_passkey(body.credential, request)
    data["passkey_set"] = True
    _save_setup(data)
    _store().delete_secret("login_hash")
    _audit(request, "setup-passkey", "passkey registered")
    return {"ok": True}


@router.post("/setup/totp/begin")
def setup_totp_begin(request: Request):
    _require_https(request)
    if _enrolled():
        raise HTTPException(status_code=409, detail="An operator is already enrolled.")
    data = _require_setup(request)
    if not data.get("secret_set") and not data.get("passkey_set"):
        raise HTTPException(status_code=400, detail="Create a passkey or login secret first.")
    secret, uri = new_totp()
    data["totp_pending"] = encrypt_text(secret)
    _save_setup(data)
    return {"ok": True, "secret": secret, "otpauth_uri": uri}


@router.post("/setup/totp/confirm")
def setup_totp_confirm(body: CodeIn, request: Request):
    _require_https(request)
    if _enrolled():
        raise HTTPException(status_code=409, detail="An operator is already enrolled.")
    data = _require_setup(request)
    pending = data.get("totp_pending")
    if not pending:
        raise HTTPException(status_code=400, detail="Start authenticator setup first.")
    secret = decrypt_text(pending)
    if not verify_totp(secret, body.code):
        _fail(request, "setup", "bad authenticator code")
        raise HTTPException(status_code=401, detail="That authenticator code is wrong.")
    if not data.get("secret_set") and not data.get("passkey_set"):
        raise HTTPException(status_code=400, detail="Create a passkey or login secret first.")
    _store().put_secret("totp", encrypt_text(secret))
    if data.get("passkey_set"):
        _store().delete_secret("login_hash")
    plain, hashes = new_recovery_codes()
    _store().replace_recovery(hashes)
    _store().put_secret("enrolled", "1")
    token = request.cookies.get(COOKIE_SETUP)
    if token:
        _store().pop_challenge(hash_token(token))
    delete_bootstrap_file()
    response = JSONResponse({"ok": True, "recovery_codes": plain})
    clear_auth_cookie(response, COOKIE_SETUP, request)
    _audit(request, "enrolled", "operator enrolled")
    return response


@router.post("/login/secret")
def login_secret(body: SecretIn, request: Request):
    _require_https(request)
    _locked(request, "login", LOGIN_FAIL_LIMIT)
    if not _enrolled():
        raise HTTPException(status_code=409, detail="Enroll the operator before signing in.")
    if _has_passkey():
        _fail(request, "login", "secret rejected because a passkey exists")
        raise HTTPException(status_code=401, detail="Sign-in failed.")
    stored = _store().get_secret("login_hash") or ""
    if not body.secret or not stored or not verify_login_secret(body.secret, stored):
        _fail(request, "login", "bad login secret")
        raise HTTPException(status_code=401, detail="Sign-in failed.")
    response = JSONResponse({"ok": True, "need_totp": True})
    _issue_pending(response, request, "secret")
    _audit(request, "login-secret", "first factor accepted")
    return response


@router.post("/login/passkey/options")
def login_passkey_options(request: Request):
    _require_https(request)
    _locked(request, "login", LOGIN_FAIL_LIMIT)
    if not _enrolled() or not _has_passkey():
        raise HTTPException(status_code=400, detail="No passkey is enrolled.")
    return _passkey_options(request, setup=False)


@router.post("/login/passkey/finish")
def login_passkey_finish(body: CredentialIn, request: Request):
    _require_https(request)
    _locked(request, "login", LOGIN_FAIL_LIMIT)
    if not _finish_passkey(body.credential, request, authentication=True):
        _fail(request, "login", "bad passkey")
        raise HTTPException(status_code=401, detail="Sign-in failed.")
    response = JSONResponse({"ok": True, "need_totp": True})
    _issue_pending(response, request, "passkey")
    _audit(request, "login-passkey", "passkey accepted")
    return response


@router.post("/login/totp")
def login_totp(body: CodeIn, request: Request):
    _require_https(request)
    _locked(request, "login", LOGIN_FAIL_LIMIT)
    pending = _require_pending(request)
    blob = _store().get_secret("totp")
    if not blob:
        raise HTTPException(status_code=409, detail="Authenticator is not enrolled.")
    if not verify_totp(decrypt_text(blob), body.code):
        _fail(request, "login", "bad authenticator code")
        raise HTTPException(status_code=401, detail="That authenticator code is wrong.")
    _store().delete_session(pending["token_hash"])
    _succeed(request, "login")
    response = JSONResponse({"ok": True})
    clear_auth_cookie(response, COOKIE_PENDING, request)
    _issue_session(response, request, limited=False)
    _audit(request, "login", "session started")
    return response


@router.post("/login/recovery")
def login_recovery(body: CodeIn, request: Request):
    _require_https(request)
    _locked(request, "login", LOGIN_FAIL_LIMIT)
    if not _enrolled():
        raise HTTPException(status_code=409, detail="Enroll the operator before signing in.")
    if not _store().consume_recovery(hash_recovery(body.code)):
        _fail(request, "login", "bad recovery code")
        raise HTTPException(status_code=401, detail="Sign-in failed.")
    _succeed(request, "login")
    response = JSONResponse({"ok": True, "limited": True})
    _issue_session(response, request, limited=True, flags="recovery")
    _audit(request, "recovery", "recovery code accepted")
    return response


@router.post("/passkey/options")
def add_passkey_options(request: Request):
    _full_session(request)
    return _passkey_options(request, setup=False, registering=True)


@router.post("/passkey/finish")
def add_passkey_finish(body: CredentialIn, request: Request):
    _full_session(request)
    _finish_passkey(body.credential, request)
    _store().delete_secret("login_hash")
    _audit(request, "passkey-added", "passkey replaced the login secret")
    return {"ok": True, "login_secret_disabled": True}


@router.post("/reenroll/secret")
def reenroll_secret(request: Request):
    row = _limited_or_full(request)
    if not row.get("limited"):
        raise HTTPException(status_code=400, detail="Use Add passkey while you are signed in.")
    if webauthn_available(request_origin(request), request_rp_id(request)):
        raise HTTPException(status_code=400, detail="Create a passkey on this origin.")
    secret = new_login_secret()
    _store().put_secret("login_hash", hash_login_secret(secret))
    flags = _add_flag(row.get("flags") or "", "secret")
    _store().touch_session(row["token_hash"], _now(), flags=flags)
    return {"ok": True, "login_secret": secret}


@router.post("/reenroll/passkey/options")
def reenroll_passkey_options(request: Request):
    row = _limited_or_full(request)
    if not row.get("limited"):
        raise HTTPException(status_code=400, detail="Use Add passkey while you are signed in.")
    return _passkey_options(request, setup=False, registering=True)


@router.post("/reenroll/passkey/finish")
def reenroll_passkey_finish(body: CredentialIn, request: Request):
    row = _limited_or_full(request)
    if not row.get("limited"):
        raise HTTPException(status_code=400, detail="Use Add passkey while you are signed in.")
    _finish_passkey(body.credential, request)
    _store().delete_secret("login_hash")
    flags = _add_flag(row.get("flags") or "", "passkey")
    _store().touch_session(row["token_hash"], _now(), flags=flags)
    return {"ok": True}


@router.post("/reenroll/totp/begin")
def reenroll_totp_begin(request: Request):
    row = _limited_or_full(request)
    if not row.get("limited"):
        raise HTTPException(status_code=403, detail="Recovery sign-in required.")
    secret, uri = new_totp()
    flags = _add_flag(row.get("flags") or "", "")
    # Stash the pending secret on the session flags is too small. Use a challenge.
    challenge_id = "totp-" + row["token_hash"]
    _store().put_challenge(challenge_id, "reenroll-totp", "", encrypt_text(secret), _now() + timedelta(minutes=10))
    _store().touch_session(row["token_hash"], _now(), flags=flags)
    return {"ok": True, "secret": secret, "otpauth_uri": uri}


@router.post("/reenroll/totp/confirm")
def reenroll_totp_confirm(body: CodeIn, request: Request):
    row = _limited_or_full(request)
    if not row.get("limited"):
        raise HTTPException(status_code=403, detail="Recovery sign-in required.")
    challenge = _store().pop_challenge("totp-" + row["token_hash"])
    if not challenge:
        raise HTTPException(status_code=400, detail="Start authenticator setup first.")
    secret = decrypt_text(challenge.get("payload") or "")
    if not verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="That authenticator code is wrong.")
    _store().put_secret("totp", encrypt_text(secret))
    flags = _add_flag(row.get("flags") or "", "totp")
    _store().touch_session(row["token_hash"], _now(), flags=flags)
    return {"ok": True}


@router.post("/reenroll/finish")
def reenroll_finish(request: Request):
    row = _limited_or_full(request)
    if not row.get("limited"):
        raise HTTPException(status_code=400, detail="Already signed in.")
    flags = set((row.get("flags") or "").split(","))
    if "totp" not in flags or not (("passkey" in flags) or ("secret" in flags)):
        raise HTTPException(status_code=400, detail="Replace a passkey or login secret, and the authenticator, first.")
    plain, hashes = new_recovery_codes()
    _store().replace_recovery(hashes)
    _store().touch_session(row["token_hash"], _now(), flags="", limited=False)
    _audit(request, "reenroll", "recovery completed")
    return {"ok": True, "recovery_codes": plain}


def _add_flag(flags: str, flag: str) -> str:
    parts = {item for item in flags.split(",") if item}
    if flag:
        parts.add(flag)
    return ",".join(sorted(parts))


def _passkey_options(request: Request, setup: bool, registering: bool | None = None):
    _require_https(request)
    origin = request_origin(request)
    rp_id = request_rp_id(request)
    if not webauthn_available(origin, rp_id):
        raise HTTPException(
            status_code=400,
            detail="Passkeys need HTTPS and a domain name. An IP address or plain HTTP cannot register one.",
        )
    registering = setup if registering is None else registering
    if registering and setup:
        _require_setup(request)
    try:
        from webauthn import generate_authentication_options, generate_registration_options, options_to_json
        from webauthn.helpers import bytes_to_base64url
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Passkey support is not installed.") from exc

    challenge = secrets.token_bytes(32)
    existing = _store().list_passkeys()
    if registering:
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="Heimdall",
            user_id=b"heimdall-operator",
            user_name="operator",
            user_display_name="Heimdall operator",
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=_b64url_to_bytes(row["credential_id"]))
                for row in existing
            ],
        )
        kind = "register"
    else:
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=_b64url_to_bytes(row["credential_id"]))
                for row in existing
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        kind = "authenticate"
    token = secrets.token_urlsafe(32)
    _store().put_challenge(
        hash_token(token),
        kind,
        bytes_to_base64url(challenge),
        origin + "|" + rp_id,
        _now() + timedelta(minutes=5),
    )
    response = JSONResponse(json.loads(options_to_json(options)))
    set_auth_cookie(response, COOKIE_CHALLENGE, token, 300, request)
    return response


def _finish_passkey(credential: dict, request: Request, authentication: bool = False) -> bool:
    origin = request_origin(request)
    rp_id = request_rp_id(request)
    token = request.cookies.get(COOKIE_CHALLENGE)
    if not token:
        raise HTTPException(status_code=400, detail="Passkey ceremony expired. Try again.")
    row = _store().pop_challenge(hash_token(token))
    if not row:
        raise HTTPException(status_code=400, detail="Passkey ceremony expired. Try again.")
    expected_kind = "authenticate" if authentication else "register"
    if row.get("kind") != expected_kind:
        raise HTTPException(status_code=400, detail="Passkey ceremony expired. Try again.")
    from webauthn import verify_authentication_response, verify_registration_response
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    challenge = base64url_to_bytes(row["challenge"])
    if authentication:
        cred_id = credential.get("id") or ""
        stored = _store().get_passkey(cred_id)
        if not stored:
            return False
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=rp_id,
                expected_origin=origin,
                credential_public_key=base64url_to_bytes(stored["public_key"]),
                credential_current_sign_count=int(stored["sign_count"]),
                require_user_verification=True,
            )
        except Exception:
            return False
        _store().set_sign_count(bytes_to_base64url(verified.credential_id), verified.new_sign_count)
        return True

    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Passkey was rejected.") from exc
    if not verified.user_verified:
        raise HTTPException(status_code=401, detail="Passkey did not verify the user.")
    _store().add_passkey(
        bytes_to_base64url(verified.credential_id),
        bytes_to_base64url(verified.credential_public_key),
        int(verified.sign_count),
    )
    return True


def _b64url_to_bytes(value: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes
    return base64url_to_bytes(value)


def session_identity_for_gate():
    """Used by the API gate. Returns an operator dict, {'limited': True}, or None."""
    request = current_request()
    if request is None:
        return None
    try:
        found = identity_from_session(request)
    except Exception:
        return None
    if not found:
        return None
    if found.get("limited"):
        return {"limited": True}
    return found
