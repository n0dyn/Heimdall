"""Pull Action1 inventory and findings into Heimdall.

Sync is operator-triggered. It reads organizations, endpoints, groups,
updates, vulnerabilities, packages, report names, and console users.
Sync does not install software or start remediations. Deleting an endpoint
and installing the Heimdall agent are separate operator actions.
Critical findings stay at severity 3 unless the operator opts in to paging.
"""

import json
import re
import urllib.parse
import uuid
from datetime import datetime, timezone

from .action1_client import REGIONS, Action1Budget, Action1Client, Action1Error, base_url_for
from .action1_store import (
    delete_endpoint_row,
    delete_link,
    endpoint_exists,
    ensure_action1_site,
    list_endpoints,
    list_links,
    load_snapshots,
    replace_endpoints,
    save_snapshot,
    upsert_link,
)
from .database_pg import get_client, get_config, insert_events_batch, set_config


_NS = uuid.UUID("6f1b1c2a-7a1e-4c3a-9b2e-0a1d5e6f7081")
_IP = re.compile(r"^[0-9a-fA-F:.]+$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_id(*parts) -> str:
    return str(uuid.uuid5(_NS, "|".join(str(part) for part in parts)))


def _pick(item: dict, *keys):
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return ""


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _source_ip(value) -> str:
    text = str(value or "").strip()
    if text and _IP.match(text) and any(mark in text for mark in (".", ":")):
        return text
    return "N/A"


def load_settings() -> dict:
    secret = get_config("ACTION1_CLIENT_SECRET", "") or ""
    return {
        "region": get_config("ACTION1_REGION", "") or "",
        "client_id": get_config("ACTION1_CLIENT_ID", "") or "",
        "client_secret": secret,
        "page_critical": (get_config("ACTION1_PAGE_CRITICAL", "false") or "").lower() == "true",
        "secret_configured": bool(secret),
    }


def public_settings() -> dict:
    settings = load_settings()
    settings.pop("client_secret", None)
    settings["regions"] = list(REGIONS)
    return settings


def save_settings(region: str, client_id: str, client_secret: str = None, page_critical: bool = False) -> dict:
    region = (region or "").strip()
    client_id = (client_id or "").strip()
    if region not in REGIONS:
        raise Action1Error(400, "Unknown Action1 region")
    if not client_id:
        raise Action1Error(400, "Action1 client id is required")
    secret = (client_secret or "").strip()
    if not secret:
        secret = get_config("ACTION1_CLIENT_SECRET", "") or ""
    if not secret:
        raise Action1Error(400, "Action1 client secret is required")
    set_config("ACTION1_REGION", region)
    set_config("ACTION1_CLIENT_ID", client_id)
    set_config("ACTION1_CLIENT_SECRET", secret)
    set_config("ACTION1_PAGE_CRITICAL", "true" if page_critical else "false")
    return public_settings()


def client_from_settings(settings: dict = None) -> Action1Client:
    settings = settings or load_settings()
    if not settings.get("client_id") or not settings.get("client_secret"):
        raise Action1Error(400, "Action1 credentials are not configured")
    return Action1Client(
        base_url_for(settings.get("region") or ""),
        settings["client_id"],
        settings["client_secret"],
    )


def _keep(items, complete: bool) -> bool:
    return bool(items) or complete


def refresh_organizations(client: Action1Client = None) -> list[dict]:
    client = client or client_from_settings()
    items, complete, _total = client.list_collection("/organizations", max_pages=3, max_items=100)
    orgs = []
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        orgs.append({
            "id": str(item.get("id")),
            "name": str(_pick(item, "name") or item.get("id")),
            "description": str(_pick(item, "description")),
        })
    if _keep(orgs, complete):
        save_snapshot("organizations", "", orgs)
    if client.budget_hit:
        raise Action1Budget()
    return orgs


def link_organization(action1_org_id: str, action1_org_name: str, client_id: str) -> dict:
    action1_org_id = (action1_org_id or "").strip()
    client_id = (client_id or "").strip()
    if not action1_org_id or not client_id:
        raise Action1Error(400, "Action1 organization and Heimdall organization are required")
    if not get_client(client_id):
        raise Action1Error(404, "Heimdall organization was not found")
    site_id = ensure_action1_site(client_id)
    if not upsert_link(action1_org_id, action1_org_name or action1_org_id, client_id, site_id):
        raise Action1Error(500, "Could not store the Action1 link")
    return {
        "action1_org_id": action1_org_id,
        "action1_org_name": action1_org_name or action1_org_id,
        "client_id": client_id,
        "site_id": site_id,
    }


def unlink_organization(action1_org_id: str) -> bool:
    return delete_link((action1_org_id or "").strip())


def _critical(label: str, score) -> bool:
    if str(label or "").strip().lower() == "critical":
        return True
    number = _as_float(score)
    return number is not None and number >= 9


def _severity(kind: str, page_critical: bool, label: str = "", score=None) -> int:
    if kind == "other_update":
        return 2
    if _critical(label, score) or kind == "critical_update":
        return 4 if page_critical else 3
    return 3


def _base_event(link: dict, host: str, user: str, source_ip: str, event_type: str,
                severity: int, message: str, signature: str, event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": _now(),
        "source_host": host or "action1",
        "os_type": "ACTION1",
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip or "N/A",
        "user": user or "system",
        "raw_message": message[:4000],
        "client_id": link["client_id"],
        "site_id": link["site_id"],
        "signature": signature or None,
        "category": "Action1",
        "action": "detected",
    }


def _endpoint_row(item: dict) -> dict:
    endpoint_id = str(_pick(item, "id"))
    return {
        "endpoint_id": endpoint_id,
        "name": str(_pick(item, "name") or endpoint_id),
        "status": str(_pick(item, "status")),
        "platform": str(_pick(item, "platform")),
        "os_name": str(_pick(item, "OS", "os")),
        "address": str(_pick(item, "address")),
        "external_address": str(_pick(item, "external_address")),
        "user_name": str(_pick(item, "user")),
        "last_seen": str(_pick(item, "last_seen")),
        "agent_version": str(_pick(item, "agent_version")),
        "missing_critical_updates": _as_int(_pick(item, "missing_critical_updates")),
        "missing_other_updates": _as_int(_pick(item, "missing_other_updates")),
        "comment": str(_pick(item, "comment")),
    }


def events_from_endpoint(item: dict, link: dict, page_critical: bool) -> list[dict]:
    row = _endpoint_row(item)
    if not row["endpoint_id"]:
        return []
    org_id = link["action1_org_id"]
    org_name = link.get("action1_org_name") or org_id
    host = row["name"]
    user = row["user_name"]
    source = _source_ip(row["address"] or row["external_address"])
    events = []
    critical = row["missing_critical_updates"]
    other = row["missing_other_updates"]
    if critical > 0:
        events.append(_base_event(
            link, host, user, source, "MISSING_UPDATE",
            _severity("critical_update", page_critical, "Critical"),
            (
                f"Action1 missing critical updates: {critical} on {host} "
                f"({org_name}). Status {row['status'] or 'unknown'}."
            ),
            f"missing-critical:{critical}",
            _event_id("missing", org_id, row["endpoint_id"], "critical", critical),
        ))
    if other > 0:
        events.append(_base_event(
            link, host, user, source, "MISSING_UPDATE",
            _severity("other_update", page_critical),
            f"Action1 missing other updates: {other} on {host} ({org_name}).",
            f"missing-other:{other}",
            _event_id("missing", org_id, row["endpoint_id"], "other", other),
        ))
    return events


def event_from_update(item: dict, link: dict, page_critical: bool):
    if not isinstance(item, dict):
        return None
    update_id = str(_pick(item, "id"))
    name = str(_pick(item, "name", "update_name", "title") or update_id)
    if not update_id and not name:
        return None
    label = str(_pick(item, "severity", "severity_name"))
    score = _pick(item, "cvss_score", "cvss")
    host = str(_pick(item, "endpoint_name") or link.get("action1_org_name") or "action1")
    if _critical(label, score):
        severity = _severity("critical_update", page_critical, label, score)
    elif label.lower() == "high":
        severity = 3
    else:
        severity = 2
    key = update_id or name
    return _base_event(
        link, host, "system", "N/A", "MISSING_UPDATE", severity,
        f"Action1 update {name}. Severity {label or 'unspecified'}.",
        name,
        _event_id("update", link["action1_org_id"], key),
    )


def event_from_vulnerability(item: dict, link: dict, page_critical: bool):
    if not isinstance(item, dict):
        return None
    cve = str(_pick(item, "cve_id", "cve", "id", "name"))
    if not cve:
        return None
    title = str(_pick(item, "name", "title") or cve)
    label = str(_pick(item, "severity", "severity_name", "risk"))
    score = _pick(item, "cvss_score", "cvss", "cvss3_score", "score")
    product = str(_pick(item, "product", "software", "software_name"))
    extra = f" Product {product}." if product else ""
    score_text = f" CVSS {score}." if score not in ("", None) else ""
    return _base_event(
        link,
        str(link.get("action1_org_name") or link["action1_org_id"]),
        "system",
        "N/A",
        "VULNERABILITY",
        _severity("vulnerability", page_critical, label, score),
        f"Action1 vulnerability {cve}: {title}. Severity {label or 'unspecified'}.{score_text}{extra}",
        cve,
        _event_id("vuln", link["action1_org_id"], cve),
    )


def _remember(kind: str, org_id: str, items, complete: bool):
    if _keep(items, complete):
        save_snapshot(kind, org_id, items)


def _snapshot_items(kind: str, org_id: str) -> list:
    for bucket in load_snapshots().get(kind) or []:
        if (bucket.get("action1_org_id") or "") == (org_id or ""):
            return list(bucket.get("items") or [])
    return []


def _dedupe(items) -> list:
    seen = set()
    kept = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("cve_id") or item.get("id") or item.get("name") or "")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        kept.append(item)
    return kept


def _load_cursors() -> dict:
    raw = get_config("ACTION1_CURSORS", "") or ""
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _save_cursors(cursors: dict):
    set_config("ACTION1_CURSORS", json.dumps(cursors))


def _note_budget(summary: dict, message: str):
    summary["budget"] = True
    summary["truncated"] = True
    if message not in summary["errors"]:
        summary["errors"].append(message)


def _mark_partial(summary: dict, name: str, done: bool):
    if not done and name not in summary["partial"]:
        summary["partial"].append(name)
        summary["truncated"] = True


def _sync_linked(client: Action1Client, settings: dict, summary: dict, cursors: dict) -> dict:
    """Collect linked-org findings first. A short package sample is not a failed sync."""
    try:
        orgs = refresh_organizations(client)
        summary["organizations"] = len(orgs)
        names = {org["id"]: org["name"] for org in orgs}
    except Action1Budget:
        _note_budget(summary, "Stopped early while listing organizations")
        return summary
    except Action1Error as exc:
        summary["errors"].append(exc.detail)
        return summary

    page_critical = settings["page_critical"]
    for link in list_links():
        org_id = link["action1_org_id"]
        label = link.get("action1_org_name") or org_id
        if org_id in names and names[org_id] != link.get("action1_org_name"):
            link["action1_org_name"] = names[org_id]
            label = names[org_id]
            upsert_link(org_id, names[org_id], link["client_id"], link["site_id"])
        try:
            org_path = urllib.parse.quote(org_id, safe="")
            endpoints, complete, _total = client.list_collection(
                f"/endpoints/managed/{org_path}", max_pages=3, max_items=150,
            )
            rows = [_endpoint_row(item) for item in endpoints if isinstance(item, dict)]
            if rows or complete:
                summary["endpoints"] += replace_endpoints(org_id, link["client_id"], rows, prune=complete)
            events = []
            for item in endpoints:
                if isinstance(item, dict):
                    events.extend(events_from_endpoint(item, link, page_critical))
            _mark_partial(summary, "endpoints", complete)
            if client.budget_hit:
                _note_budget(summary, f"{label}: stopped early")
                if events:
                    inserted, skipped = insert_events_batch(events)
                    summary["events_inserted"] += inserted
                    summary["events_skipped"] += skipped
                break

            updates, updates_done, _updates_total = client.list_collection(
                f"/updates/{org_path}", max_pages=3, max_items=200,
            )
            _remember("updates", org_id, updates, updates_done)
            summary["updates"] += len(updates)
            for item in updates:
                event = event_from_update(item, link, page_critical)
                if event:
                    events.append(event)
            _mark_partial(summary, "updates", updates_done)
            if client.budget_hit:
                _note_budget(summary, f"{label}: stopped early")
                if events:
                    inserted, skipped = insert_events_batch(events)
                    summary["events_inserted"] += inserted
                    summary["events_skipped"] += skipped
                break

            cursor_key = f"vulnerabilities:{org_id}"
            start = _as_int(cursors.get(cursor_key))
            vulns, vulns_done, vulns_total = client.list_collection(
                f"/vulnerabilities/{org_path}",
                max_pages=6,
                max_items=2500,
                limit=500,
                fields=False,
                start=start,
            )
            if vulns_total is not None:
                summary["vulnerabilities_total"] = int(summary.get("vulnerabilities_total") or 0) + int(vulns_total)
            stored = list(vulns)
            if start:
                stored = _dedupe(_snapshot_items("vulnerabilities", org_id) + stored)
            _remember("vulnerabilities", org_id, stored, vulns_done or bool(stored))
            summary["vulnerabilities"] += len(vulns)
            for item in vulns:
                event = event_from_vulnerability(item, link, page_critical)
                if event:
                    events.append(event)
            if vulns_done:
                cursors.pop(cursor_key, None)
            else:
                cursors[cursor_key] = start + len(vulns)
            _mark_partial(summary, "vulnerabilities", vulns_done)
            if client.budget_hit:
                _note_budget(summary, f"{label}: stopped early")
                if events:
                    inserted, skipped = insert_events_batch(events)
                    summary["events_inserted"] += inserted
                    summary["events_skipped"] += skipped
                break

            groups, groups_done, _groups_total = client.list_collection(
                f"/endpoints/groups/{org_path}", max_pages=2, max_items=100,
            )
            _remember("groups", org_id, groups, groups_done)
            summary["groups"] += len(groups)
            _mark_partial(summary, "groups", groups_done)
            if events:
                inserted, skipped = insert_events_batch(events)
                summary["events_inserted"] += inserted
                summary["events_skipped"] += skipped
            if client.budget_hit:
                _note_budget(summary, f"{label}: stopped early")
                break
        except Action1Budget:
            _note_budget(summary, f"{label}: stopped early")
            break
        except Action1Error as exc:
            summary["errors"].append(f"{label}: {exc.detail}")

    if summary["budget"]:
        return summary

    for kind, path in (
        ("packages", "/packages/all"),
        ("reports", "/reports/all"),
        ("users", "/users"),
    ):
        try:
            items, complete, total = client.list_collection(path, max_pages=2, max_items=100)
            _remember(kind, "", items, complete)
            summary[kind] = len(items)
            if total is not None:
                summary[f"{kind}_total"] = total
            if client.budget_hit:
                break
        except Action1Budget:
            break
        except Action1Error as exc:
            summary["errors"].append(f"{kind}: {exc.detail}")
    return summary


def sync_action1(client: Action1Client = None) -> dict:
    settings = load_settings()
    client = client or client_from_settings(settings)
    summary = {
        "synced_at": _now(),
        "organizations": 0,
        "endpoints": 0,
        "events_inserted": 0,
        "events_skipped": 0,
        "groups": 0,
        "updates": 0,
        "vulnerabilities": 0,
        "packages": 0,
        "reports": 0,
        "users": 0,
        "truncated": False,
        "budget": False,
        "partial": [],
        "errors": [],
    }
    cursors = _load_cursors()
    try:
        return _sync_linked(client, settings, summary, cursors)
    finally:
        summary["partial"] = list(dict.fromkeys(summary["partial"]))
        _save_cursors(cursors)
        _store_summary(summary)


def _store_summary(summary: dict):
    set_config("ACTION1_LAST_SYNC", json.dumps(summary))


def last_sync() -> dict:
    raw = get_config("ACTION1_LAST_SYNC", "") or ""
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def action1_state(client_id: str = None) -> dict:
    """Action1 view for one Heimdall organization, or every link when client_id is omitted."""
    settings = public_settings()
    snapshots = load_snapshots()
    scoped = (client_id or "").strip()
    all_links = list_links()
    links = [link for link in all_links if not scoped or link.get("client_id") == scoped]
    allowed = {link.get("action1_org_id") for link in links}
    by_org = {link.get("action1_org_id"): link for link in all_links}

    def decorate(item, org_id: str) -> dict:
        link = by_org.get(org_id) or {}
        if isinstance(item, dict):
            copied = dict(item)
        else:
            copied = {"value": item}
        copied["action1_org_id"] = org_id or copied.get("action1_org_id") or ""
        if link.get("client_id"):
            copied["client_id"] = link["client_id"]
        if link.get("action1_org_name"):
            copied["action1_org_name"] = link["action1_org_name"]
        return copied

    def flat(kind: str, mode: str) -> list:
        rows = []
        for bucket in snapshots.get(kind) or []:
            org_id = bucket.get("action1_org_id") or ""
            if mode == "linked" and org_id not in allowed:
                continue
            if mode == "account" and scoped and not links:
                continue
            for item in bucket.get("items") or []:
                rows.append(decorate(item, org_id))
        return rows

    return {
        "settings": settings,
        "links": links,
        "endpoints": list_endpoints(scoped or None),
        "organizations": flat("organizations", "all"),
        "groups": flat("groups", "linked"),
        "updates": flat("updates", "linked"),
        "vulnerabilities": flat("vulnerabilities", "linked"),
        "packages": flat("packages", "account"),
        "reports": flat("reports", "account"),
        "users": flat("users", "account"),
        "last_sync": last_sync(),
    }


def remove_remote_endpoint(action1_org_id: str, endpoint_id: str) -> dict:
    action1_org_id = (action1_org_id or "").strip()
    endpoint_id = (endpoint_id or "").strip()
    if not action1_org_id or not endpoint_id:
        raise Action1Error(400, "Action1 organization and endpoint are required")
    if not endpoint_exists(action1_org_id, endpoint_id):
        raise Action1Error(404, "Action1 endpoint was not found")
    client = client_from_settings()
    try:
        client.delete_endpoint(action1_org_id, endpoint_id)
    except Action1Error as exc:
        if exc.status != 404:
            raise
    delete_endpoint_row(action1_org_id, endpoint_id)
    return {"action1_org_id": action1_org_id, "endpoint_id": endpoint_id}
