"""Move one endpoint between organizations and sites.

The route and the tests both call move_endpoint. Ingest and heartbeat call
lookup_placement so a later write stays on the destination instead of the
agent key's original organization.
"""

import psycopg2

from .database_pg import get_conn, return_conn

_ENDPOINT_TABLES = ("heartbeats", "logs", "system_status", "host_metrics")


class PlacementError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def lookup_placement(origin_client_id: str, source_host: str):
    """Current organization and site for a host still reporting with an older key."""
    if not origin_client_id or not source_host:
        return None
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT client_id, site_id FROM endpoint_placements
            WHERE origin_client_id = %s AND source_host = %s
            """,
            (origin_client_id, source_host),
        )
        row = cursor.fetchone()
        return_conn(conn)
        conn = None
        if not row:
            return None
        return {"client_id": row[0], "site_id": row[1]}
    except psycopg2.OperationalError:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
            return_conn(conn)
        return None
    except Exception:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
            return_conn(conn)
        raise


def _endpoint_exists(cursor, source_host: str, client_id: str) -> bool:
    for table in _ENDPOINT_TABLES:
        cursor.execute(
            f"SELECT 1 FROM {table} WHERE source_host = %s AND client_id = %s LIMIT 1",
            (source_host, client_id),
        )
        if cursor.fetchone():
            return True
    cursor.execute(
        """
        SELECT 1 FROM endpoint_placements
        WHERE source_host = %s AND client_id = %s LIMIT 1
        """,
        (source_host, client_id),
    )
    return cursor.fetchone() is not None


def move_endpoint(source_host: str, from_client_id: str, to_client_id: str, to_site_id: str) -> dict:
    """Move stored rows and future ingests for one host onto the destination site.

    The host is identified by its current name plus organization. A destination
    that already has that name is rejected so two endpoints are not merged.
    """
    source_host = (source_host or "").strip()
    from_client_id = (from_client_id or "").strip()
    to_client_id = (to_client_id or "").strip()
    to_site_id = (to_site_id or "").strip()
    if not source_host or not from_client_id or not to_client_id or not to_site_id:
        raise PlacementError(400, "Endpoint, organization, and destination site are required")

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM clients WHERE id = %s", (to_client_id,))
        if cursor.fetchone() is None:
            raise PlacementError(404, "Destination organization not found")
        cursor.execute("SELECT client_id FROM sites WHERE id = %s", (to_site_id,))
        site = cursor.fetchone()
        if site is None or site[0] != to_client_id:
            raise PlacementError(400, "Destination site is not in that organization")
        if not _endpoint_exists(cursor, source_host, from_client_id):
            raise PlacementError(404, "Endpoint not found in that organization")
        if to_client_id != from_client_id and _endpoint_exists(cursor, source_host, to_client_id):
            raise PlacementError(
                409,
                f"Destination organization already has an endpoint named {source_host}",
            )

        for table in _ENDPOINT_TABLES:
            cursor.execute(
                f"""
                UPDATE {table}
                SET client_id = %s, site_id = %s
                WHERE source_host = %s AND client_id = %s
                """,
                (to_client_id, to_site_id, source_host, from_client_id),
            )

        cursor.execute(
            """
            UPDATE endpoint_placements
            SET client_id = %s, site_id = %s
            WHERE source_host = %s AND client_id = %s
            """,
            (to_client_id, to_site_id, source_host, from_client_id),
        )
        if cursor.rowcount == 0:
            cursor.execute(
                """
                INSERT INTO endpoint_placements
                    (source_host, origin_client_id, client_id, site_id)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (origin_client_id, source_host) DO UPDATE SET
                    client_id = EXCLUDED.client_id,
                    site_id = EXCLUDED.site_id
                """,
                (source_host, from_client_id, to_client_id, to_site_id),
            )

        conn.commit()
        return_conn(conn)
        conn = None
        return {
            "source_host": source_host,
            "client_id": to_client_id,
            "site_id": to_site_id,
            "from_client_id": from_client_id,
        }
    except PlacementError:
        if conn:
            conn.rollback()
            return_conn(conn)
        raise
    except Exception:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
            return_conn(conn)
        raise
