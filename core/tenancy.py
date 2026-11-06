"""
MSP client/site isolation helpers.

Operator key (SIEM_API_KEY env) sees every client. Agent keys are scoped
to a single client_id. Query helpers refuse to return another client's rows.
"""

import hashlib
import secrets
from typing import Any, Iterable, Optional

from .host_metrics import DEFAULT_CLIENT_ID, DEFAULT_SITE_ID

ROLE_OPERATOR = "operator"
ROLE_AGENT = "agent"


def org_slug_from(name: str, client_id: str) -> str:
    """Stable public slug for /org/{slug} workspaces (future dedicated UIs)."""
    import re
    base = re.sub(r"[^a-z0-9-]+", "-", (name or "").lower()).strip("-")
    if not base:
        base = "org"
    if client_id and client_id not in (base,):
        # Keep id as slug when it already looks like name-suffix.
        if str(client_id).startswith(base):
            return client_id
    return client_id or base


def decorate_org(row: Optional[dict]) -> Optional[dict]:
    """Add organization workspace fields without changing stored client_id."""
    if not row:
        return row
    out = dict(row)
    slug = out.get("slug") or out.get("id")
    out["slug"] = slug
    out["organization"] = out.get("name")
    out["workspace_path"] = f"/org/{slug}"
    out["workspace_hash"] = f"#/org/{slug}"
    return out


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_api_key(prefix: str = "hk") -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def key_prefix(raw: str) -> str:
    if not raw:
        return ""
    return raw[:8]


def resolve_identity(api_key: Optional[str], operator_key: str, lookup) -> Optional[dict]:
    """
    Resolve an API key to {role, client_id, site_id, label}.

    `lookup(key_hash)` returns a stored key row or None. The operator key
    is compared in constant-ish time against the env value and is not stored.
    """
    if not api_key:
        return None
    if operator_key and secrets.compare_digest(api_key, operator_key):
        return {
            "role": ROLE_OPERATOR,
            "client_id": None,
            "site_id": None,
            "label": "operator",
        }
    row = lookup(hash_api_key(api_key))
    if not row:
        return None
    return {
        "role": row.get("role") or ROLE_AGENT,
        "client_id": row.get("client_id") or DEFAULT_CLIENT_ID,
        "site_id": row.get("site_id") or DEFAULT_SITE_ID,
        "label": row.get("label") or "",
    }


def site_belongs_to_client(site_id: Optional[str], client_id: Optional[str]) -> bool:
    if not site_id or not client_id:
        return False
    return site_id == client_id or str(site_id).startswith(str(client_id) + "-")


def effective_site_id(identity: dict, requested: Optional[str] = None) -> Optional[str]:
    """Operator may filter by site. Agents may pick a site inside their client."""
    if not identity:
        return requested or DEFAULT_SITE_ID
    if identity.get("role") == ROLE_OPERATOR:
        return requested or None
    pinned_client = identity.get("client_id") or DEFAULT_CLIENT_ID
    if requested and site_belongs_to_client(requested, pinned_client):
        return requested
    if requested:
        return f"{pinned_client}-{requested}"
    return identity.get("site_id") or DEFAULT_SITE_ID


def effective_client_id(identity: dict, requested: Optional[str] = None) -> Optional[str]:
    """
    Agents are pinned to their client. Operators may optionally filter.
    Returning None means "all clients" (operator, no filter).
    """
    if not identity:
        return DEFAULT_CLIENT_ID
    if identity.get("role") == ROLE_OPERATOR:
        return requested or None
    return identity.get("client_id") or DEFAULT_CLIENT_ID


def stamp_client(record: dict, identity: dict, placement_for=None) -> dict:
    """Copy identity client/site onto a write payload (agents cannot spoof).

    placement_for(origin_client_id, source_host) returns the destination after
    an endpoint move. When it returns a row, that destination wins over the key.
    """
    out = dict(record)
    if identity.get("role") == ROLE_OPERATOR:
        out.setdefault("client_id", record.get("client_id") or DEFAULT_CLIENT_ID)
        out.setdefault("site_id", record.get("site_id") or DEFAULT_SITE_ID)
        return out
    client_id = identity.get("client_id") or DEFAULT_CLIENT_ID
    if placement_for:
        placed = placement_for(client_id, out.get("source_host"))
        if placed and placed.get("client_id"):
            out["client_id"] = placed["client_id"]
            out["site_id"] = placed.get("site_id") or DEFAULT_SITE_ID
            return out
    out["client_id"] = client_id
    requested_site = record.get("site_id")
    if requested_site and site_belongs_to_client(requested_site, client_id):
        out["site_id"] = requested_site
    elif requested_site:
        out["site_id"] = f"{client_id}-{requested_site}"
    else:
        out["site_id"] = identity.get("site_id") or DEFAULT_SITE_ID
    return out


def scoped_rows(rows: Iterable[dict], client_id: Optional[str]) -> list[dict]:
    """Filter an in-memory collection. None client_id = operator, no filter."""
    if not client_id:
        return list(rows)
    out = []
    for row in rows:
        row_cid = row.get("client_id") or DEFAULT_CLIENT_ID
        if row_cid == client_id:
            out.append(row)
    return out


def assert_host_visible(row: Optional[dict], client_id: Optional[str]) -> bool:
    if row is None:
        return False
    if not client_id:
        return True
    return (row.get("client_id") or DEFAULT_CLIENT_ID) == client_id
