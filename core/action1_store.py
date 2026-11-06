"""Action1 rows: org links, endpoint inventory, and read-only snapshots.

Inventory lives here, not in heartbeats. Vulnerability logs use os_type
ACTION1 so get_host_status does not turn them into host-down alerts.
A Heimdall agent is installed only when a real agent heartbeat matches
the Action1 computer name. Otherwise the computer still appears as a
host and is marked as needing the agent.
"""

import json

from psycopg2 import extras

from .database_pg import create_site, get_conn, get_site, return_conn


_SENSITIVE = {
    "secret", "password", "client_secret", "access_token", "refresh_token", "token",
}

AGENT_INSTALLED = "installed"
AGENT_NEEDS_INSTALL = "needs_install"
LABEL_INSTALLED = "Heimdall agent installed"
LABEL_NEEDS_INSTALL = "Heimdall agent needs install"


def host_match_key(name: str) -> str:
    """Short hostname used to match an Action1 computer to an agent check-in."""
    text = (name or "").strip().lower().rstrip(".")
    if text.endswith(".local"):
        text = text[:-6]
    return text.split(".")[0]


def scrub(value):
    """Drop credential-shaped keys before a snapshot is stored."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if str(key).lower() in _SENSITIVE:
                continue
            cleaned[key] = scrub(item)
        return cleaned
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str) and len(value) > 500:
        return value[:500]
    return value


def ensure_action1_site(client_id: str) -> str:
    site_id = f"{client_id}-action1"
    if get_site(site_id):
        return site_id
    if create_site(site_id, client_id, "Action1") or get_site(site_id):
        return site_id
    raise RuntimeError("Could not create the Action1 site")


def upsert_link(action1_org_id: str, action1_org_name: str, client_id: str, site_id: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO action1_links (
                action1_org_id, action1_org_name, client_id, site_id, updated_at
            ) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (action1_org_id) DO UPDATE SET
                action1_org_name = EXCLUDED.action1_org_name,
                client_id = EXCLUDED.client_id,
                site_id = EXCLUDED.site_id,
                updated_at = CURRENT_TIMESTAMP
            """,
            (action1_org_id, action1_org_name or "", client_id, site_id),
        )
        conn.commit()
        return_conn(conn)
        return True
    except Exception as exc:
        print(f"Error linking Action1 organization: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def list_links() -> list[dict]:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute(
            """
            SELECT action1_org_id, action1_org_name, client_id, site_id, updated_at
            FROM action1_links
            ORDER BY action1_org_name, action1_org_id
            """
        )
        rows = []
        for row in cursor.fetchall():
            item = dict(row)
            updated = item.get("updated_at")
            if updated is not None and not isinstance(updated, str):
                item["updated_at"] = updated.isoformat()
            rows.append(item)
        return_conn(conn)
        return rows
    except Exception as exc:
        print(f"Error listing Action1 links: {exc}")
        if conn:
            return_conn(conn)
        return []


def delete_link(action1_org_id: str) -> bool:
    """Drop the link and its inventory. Stored SIEM events stay."""
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM action1_endpoints WHERE action1_org_id = %s",
            (action1_org_id,),
        )
        cursor.execute(
            "DELETE FROM action1_snapshots WHERE action1_org_id = %s",
            (action1_org_id,),
        )
        cursor.execute(
            "DELETE FROM action1_links WHERE action1_org_id = %s",
            (action1_org_id,),
        )
        removed = cursor.rowcount > 0
        conn.commit()
        return_conn(conn)
        return removed
    except Exception as exc:
        print(f"Error unlinking Action1 organization: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def replace_endpoints(action1_org_id: str, client_id: str, rows: list[dict], prune: bool) -> int:
    """Upsert inventory. Prune only when the page walk finished."""
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        seen = []
        for row in rows:
            endpoint_id = row.get("endpoint_id")
            if not endpoint_id:
                continue
            seen.append(endpoint_id)
            cursor.execute(
                """
                INSERT INTO action1_endpoints (
                    action1_org_id, endpoint_id, client_id, name, status, platform,
                    os_name, address, external_address, user_name, last_seen,
                    agent_version, missing_critical_updates, missing_other_updates,
                    comment, synced_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
                )
                ON CONFLICT (action1_org_id, endpoint_id) DO UPDATE SET
                    client_id = EXCLUDED.client_id,
                    name = EXCLUDED.name,
                    status = EXCLUDED.status,
                    platform = EXCLUDED.platform,
                    os_name = EXCLUDED.os_name,
                    address = EXCLUDED.address,
                    external_address = EXCLUDED.external_address,
                    user_name = EXCLUDED.user_name,
                    last_seen = EXCLUDED.last_seen,
                    agent_version = EXCLUDED.agent_version,
                    missing_critical_updates = EXCLUDED.missing_critical_updates,
                    missing_other_updates = EXCLUDED.missing_other_updates,
                    comment = EXCLUDED.comment,
                    synced_at = CURRENT_TIMESTAMP
                """,
                (
                    action1_org_id, endpoint_id, client_id, row.get("name") or "",
                    row.get("status") or "", row.get("platform") or "", row.get("os_name") or "",
                    row.get("address") or "", row.get("external_address") or "",
                    row.get("user_name") or "", row.get("last_seen") or "",
                    row.get("agent_version") or "",
                    int(row.get("missing_critical_updates") or 0),
                    int(row.get("missing_other_updates") or 0),
                    row.get("comment") or "",
                ),
            )
        if prune:
            if seen:
                cursor.execute(
                    """
                    DELETE FROM action1_endpoints
                    WHERE action1_org_id = %s AND NOT (endpoint_id = ANY(%s))
                    """,
                    (action1_org_id, seen),
                )
            else:
                cursor.execute(
                    "DELETE FROM action1_endpoints WHERE action1_org_id = %s",
                    (action1_org_id,),
                )
        conn.commit()
        return_conn(conn)
        return len(seen)
    except Exception as exc:
        print(f"Error storing Action1 endpoints: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
        raise


def _agent_index(cursor, client_id: str = None) -> dict:
    """Real Heimdall agents, keyed by organization and short hostname."""
    query = """
        SELECT source_host, client_id
        FROM heartbeats
        WHERE os_type <> 'UNIFI' AND os_type <> 'ACTION1'
    """
    params = []
    if client_id:
        query += " AND client_id = %s"
        params.append(client_id)
    cursor.execute(query, params)
    index = {}
    for row in cursor.fetchall():
        source_host = row["source_host"] if isinstance(row, dict) else row[0]
        cid = row["client_id"] if isinstance(row, dict) else row[1]
        key = host_match_key(source_host)
        if not key:
            continue
        index.setdefault((cid, key), source_host)
    return index


def _stamp_heimdall_agent(row: dict, agent_host: str) -> None:
    if agent_host:
        row["heimdall_agent"] = AGENT_INSTALLED
        row["heimdall_agent_label"] = LABEL_INSTALLED
        row["heimdall_host"] = agent_host
    else:
        row["heimdall_agent"] = AGENT_NEEDS_INSTALL
        row["heimdall_agent_label"] = LABEL_NEEDS_INSTALL
        row["heimdall_host"] = ""


def list_endpoints(client_id: str = None) -> list[dict]:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        query = """
            SELECT e.action1_org_id, e.endpoint_id, e.client_id, e.name, e.status,
                   e.platform, e.os_name, e.address, e.external_address, e.user_name,
                   e.last_seen, e.agent_version, e.missing_critical_updates,
                   e.missing_other_updates, e.comment, e.synced_at,
                   l.action1_org_name, l.site_id
            FROM action1_endpoints e
            LEFT JOIN action1_links l ON l.action1_org_id = e.action1_org_id
        """
        params = []
        if client_id:
            query += " WHERE e.client_id = %s"
            params.append(client_id)
        query += " ORDER BY e.name, e.endpoint_id"
        cursor.execute(query, params)
        stored = cursor.fetchall()
        agents = _agent_index(cursor, client_id)
        rows = []
        for row in stored:
            item = dict(row)
            synced = item.get("synced_at")
            if synced is not None and not isinstance(synced, str):
                item["synced_at"] = synced.isoformat()
            key = host_match_key(item.get("name") or "")
            agent_host = agents.get((item.get("client_id"), key), "") if key else ""
            _stamp_heimdall_agent(item, agent_host)
            rows.append(item)
        return_conn(conn)
        return rows
    except Exception as exc:
        print(f"Error listing Action1 endpoints: {exc}")
        if conn:
            return_conn(conn)
        return []


def delete_endpoint_row(action1_org_id: str, endpoint_id: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            DELETE FROM action1_endpoints
            WHERE action1_org_id = %s AND endpoint_id = %s
            """,
            (action1_org_id, endpoint_id),
        )
        removed = cursor.rowcount > 0
        conn.commit()
        return_conn(conn)
        return removed
    except Exception as exc:
        print(f"Error deleting Action1 endpoint row: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def get_endpoint(action1_org_id: str, endpoint_id: str) -> dict | None:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute(
            """
            SELECT e.action1_org_id, e.endpoint_id, e.name, e.status, e.platform, e.os_name
            FROM action1_endpoints e
            WHERE e.action1_org_id = %s AND e.endpoint_id = %s
            """,
            (action1_org_id, endpoint_id),
        )
        row = cursor.fetchone()
        return_conn(conn)
        return dict(row) if row else None
    except Exception as exc:
        print(f"Error reading Action1 endpoint: {exc}")
        if conn:
            return_conn(conn)
        return None


def endpoint_exists(action1_org_id: str, endpoint_id: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM action1_endpoints
            WHERE action1_org_id = %s AND endpoint_id = %s
            """,
            (action1_org_id, endpoint_id),
        )
        found = cursor.fetchone() is not None
        return_conn(conn)
        return found
    except Exception as exc:
        print(f"Error checking Action1 endpoint: {exc}")
        if conn:
            return_conn(conn)
        return False


def save_snapshot(kind: str, action1_org_id: str, payload) -> bool:
    payload = scrub(payload)
    text = json.dumps(payload)
    if len(text) > 2000000 and isinstance(payload, list):
        kept = list(payload)
        while kept and len(text) > 2000000:
            kept = kept[:-1]
            text = json.dumps(kept)
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO action1_snapshots (kind, action1_org_id, payload, synced_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (kind, action1_org_id) DO UPDATE SET
                payload = EXCLUDED.payload,
                synced_at = CURRENT_TIMESTAMP
            """,
            (kind, action1_org_id or "", text),
        )
        conn.commit()
        return_conn(conn)
        return True
    except Exception as exc:
        print(f"Error saving Action1 snapshot: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def load_snapshots() -> dict:
    """kind -> list of {action1_org_id, items}."""
    conn = None
    grouped = {}
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute(
            "SELECT kind, action1_org_id, payload FROM action1_snapshots ORDER BY kind"
        )
        for row in cursor.fetchall():
            try:
                items = json.loads(row["payload"] or "[]")
            except json.JSONDecodeError:
                items = []
            if not isinstance(items, list):
                items = []
            grouped.setdefault(row["kind"], []).append({
                "action1_org_id": row["action1_org_id"] or "",
                "items": items,
            })
        return_conn(conn)
        return grouped
    except Exception as exc:
        print(f"Error loading Action1 snapshots: {exc}")
        if conn:
            return_conn(conn)
        return grouped
