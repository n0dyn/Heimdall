"""Docker servers belong to one Heimdall organization.

The SSH key is the hub collector key on disk. This table stores the host,
the account, and how far each log has been read. It does not store a secret.
"""

import uuid
from datetime import datetime, timezone

from .database_pg import get_conn, get_site, return_conn
from .docker_logs import DockerLogError, validate_server_fields

_PUBLIC_COLUMNS = (
    "id", "client_id", "site_id", "name", "ssh_host", "ssh_port", "ssh_user",
    "log_dir", "enabled", "created_at", "last_poll", "last_ok", "last_error",
)


def _stamp(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        text = value.isoformat()
        if value.tzinfo is None:
            return text + "Z" if not text.endswith("Z") else text
        return text
    return str(value)


def _row(record) -> dict:
    item = {column: record[column] for column in _PUBLIC_COLUMNS}
    for key in ("created_at", "last_poll", "last_ok"):
        item[key] = _stamp(item.get(key))
    item["enabled"] = bool(item.get("enabled"))
    item["ssh_port"] = int(item["ssh_port"])
    if item.get("last_ok") and not item.get("last_error"):
        item["status"] = "collecting"
    elif item.get("last_error"):
        item["status"] = "error"
    else:
        item["status"] = "waiting"
    return item


def list_docker_servers(client_id: str = None, site_id: str = None) -> list:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        query = "SELECT " + ", ".join(_PUBLIC_COLUMNS) + " FROM docker_servers WHERE 1=1"
        params = []
        if client_id:
            query += " AND client_id = %s"
            params.append(client_id)
        if site_id:
            query += " AND site_id = %s"
            params.append(site_id)
        query += " ORDER BY name"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return_conn(conn)
        return [_row(dict(zip(_PUBLIC_COLUMNS, row))) for row in rows]
    except Exception as exc:
        print(f"Error listing docker servers: {exc}")
        if conn:
            return_conn(conn)
        return []


def get_docker_server(server_id: str, client_id: str = None) -> dict:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        query = "SELECT " + ", ".join(_PUBLIC_COLUMNS) + " FROM docker_servers WHERE id = %s"
        params = [server_id]
        if client_id:
            query += " AND client_id = %s"
            params.append(client_id)
        cursor.execute(query, params)
        row = cursor.fetchone()
        return_conn(conn)
        if row is None:
            return None
        return _row(dict(zip(_PUBLIC_COLUMNS, row)))
    except Exception as exc:
        print(f"Error reading docker server: {exc}")
        if conn:
            return_conn(conn)
        return None


def create_docker_server(client_id: str, site_id: str, name: str, ssh_host: str,
                         ssh_user: str, log_dir: str, ssh_port=22) -> dict:
    fields = validate_server_fields(name, ssh_host, ssh_user, ssh_port, log_dir)
    site = get_site(site_id)
    if not site or site.get("client_id") != client_id:
        raise DockerLogError("Pick a site that belongs to this organization.")
    server_id = "docker-" + uuid.uuid4().hex[:12]
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO docker_servers (
                id, client_id, site_id, name, ssh_host, ssh_port, ssh_user, log_dir
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                server_id, client_id, site_id, fields["name"], fields["ssh_host"],
                fields["ssh_port"], fields["ssh_user"], fields["log_dir"],
            ),
        )
        conn.commit()
        return_conn(conn)
    except Exception as exc:
        if conn:
            conn.rollback()
            return_conn(conn)
        raise DockerLogError(f"Could not save the docker server: {exc}")
    return get_docker_server(server_id)


def delete_docker_server(server_id: str, client_id: str = None) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        if client_id:
            cursor.execute(
                "DELETE FROM docker_log_cursors WHERE server_id = %s AND server_id IN (SELECT id FROM docker_servers WHERE id = %s AND client_id = %s)",
                (server_id, server_id, client_id),
            )
            cursor.execute(
                "DELETE FROM docker_servers WHERE id = %s AND client_id = %s",
                (server_id, client_id),
            )
        else:
            cursor.execute("DELETE FROM docker_log_cursors WHERE server_id = %s", (server_id,))
            cursor.execute("DELETE FROM docker_servers WHERE id = %s", (server_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return_conn(conn)
        return deleted
    except Exception as exc:
        print(f"Error deleting docker server: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def get_cursors(server_id: str) -> dict:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT basename, inode, file_offset, pending, bootstrapped
            FROM docker_log_cursors WHERE server_id = %s
            """,
            (server_id,),
        )
        rows = cursor.fetchall()
        return_conn(conn)
        found = {}
        for basename, inode, offset, pending, bootstrapped in rows:
            found[basename] = {
                "inode": inode or "",
                "offset": int(offset or 0),
                "pending": pending or "",
                "bootstrapped": bool(bootstrapped),
            }
        return found
    except Exception as exc:
        print(f"Error reading docker cursors: {exc}")
        if conn:
            return_conn(conn)
        return {}


def save_cursor(server_id: str, basename: str, inode: str, offset: int,
                pending: str, bootstrapped: bool):
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO docker_log_cursors (server_id, basename, inode, file_offset, pending, bootstrapped)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (server_id, basename) DO UPDATE SET
                inode = EXCLUDED.inode,
                file_offset = EXCLUDED.file_offset,
                pending = EXCLUDED.pending,
                bootstrapped = EXCLUDED.bootstrapped
            """,
            (server_id, basename, inode or "", int(offset), pending or "", bool(bootstrapped)),
        )
        conn.commit()
        return_conn(conn)
    except Exception as exc:
        print(f"Error saving docker cursor: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)


def mark_poll(server_id: str, error: str = None, ok: bool = False):
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc)
        if ok:
            cursor.execute(
                """
                UPDATE docker_servers
                SET last_poll = %s, last_ok = %s, last_error = NULL
                WHERE id = %s
                """,
                (now, now, server_id),
            )
        else:
            cursor.execute(
                """
                UPDATE docker_servers
                SET last_poll = %s, last_error = %s
                WHERE id = %s
                """,
                (now, (error or "Collection failed")[:500], server_id),
            )
        conn.commit()
        return_conn(conn)
    except Exception as exc:
        print(f"Error updating docker poll status: {exc}")
        if conn:
            conn.rollback()
            return_conn(conn)
