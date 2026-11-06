"""
Heimdall - PostgreSQL Database Layer

PostgreSQL database management for Heimdall.
Replaces SQLite for better concurrency and reliability.
Provides unified query interface for all event data.
"""

import psycopg2
from psycopg2 import pool, extras
import os
import json
from datetime import datetime, timezone, timedelta
import time

from .host_metrics import DEFAULT_CLIENT_ID, DEFAULT_SITE_ID, query_samples as bucket_query_samples

# PostgreSQL connection configuration
DB_HOST = os.getenv("SIEM_DB_HOST", "postgres")
DB_PORT = int(os.getenv("SIEM_DB_PORT", "5432"))
DB_NAME = os.getenv("SIEM_DB_NAME", "heimdall")
DB_USER = os.getenv("SIEM_DB_USER", "heimdall")
DB_PASSWORD = os.getenv("SIEM_DB_PASSWORD", "heimdall")

# Connection pool for better performance
conn_pool = None

def init_connection_pool():
    """Initialize PostgreSQL connection pool."""
    global conn_pool
    try:
        conn_pool = psycopg2.pool.SimpleConnectionPool(
            1, 20,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=5
        )
        print(f"PostgreSQL connection pool initialized")
    except Exception as e:
        print(f"Error initializing connection pool: {e}")
        raise

def get_conn():
    """Get a connection from the pool."""
    if conn_pool is None:
        init_connection_pool()
    return conn_pool.getconn()

def return_conn(conn):
    """Return a connection to the pool."""
    if conn_pool:
        conn_pool.putconn(conn)

def init_database():
    """Initialize PostgreSQL database with tables and indexes."""
    conn = None
    retries = 10
    
    while retries > 0:
        try:
            print(f"Connecting to database... ({retries} retries left)")
            conn = get_conn()
            cursor = conn.cursor()

            # Create config table for dynamic settings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create system status table for RMM features
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_status (
                    id SERIAL PRIMARY KEY,
                    source_host TEXT UNIQUE NOT NULL,
                    os_type TEXT NOT NULL,
                    os_details TEXT,
                    cpu_usage FLOAT,
                    cpu_count INTEGER,
                    memory_total BIGINT,
                    memory_used BIGINT,
                    memory_percent FLOAT,
                    disk_info JSONB,
                    network_info JSONB,
                    top_processes JSONB,
                    boot_time TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    os_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    source_ip TEXT NOT NULL,
                    "user" TEXT NOT NULL,
                    raw_message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes for fast queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_event_type ON logs(event_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_source_ip ON logs(source_ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_os_type ON logs(os_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity ON logs(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp_ostype ON logs(timestamp DESC, os_type)
            """)

            # Create heartbeat table for agent status tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS heartbeats (
                    id SERIAL PRIMARY KEY,
                    source_host TEXT UNIQUE NOT NULL,
                    os_type TEXT NOT NULL,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_heartbeat_host ON heartbeats(source_host)
            """)

            # Create alert history table to prevent duplicate alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_history (
                    id SERIAL PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(event_id, alert_type)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_history_event ON alert_history(event_id)
            """)

            _init_metrics_and_tenancy(cursor)
            from .auth_store import init_auth_schema
            init_auth_schema(cursor)

            conn.commit()
            return_conn(conn)
            print(f"PostgreSQL database initialized")
            break # Success!
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            if conn:
                try:
                    conn.rollback()
                    return_conn(conn)
                except:
                    pass
                conn = None
            
            retries -= 1
            if retries == 0:
                print("Failed to connect to database after multiple attempts. Exiting.")
                raise e
            
            time.sleep(5)

def _optional_port(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _log_values(event_dict: dict) -> tuple:
    """Column values for one logs row. Missing network fields stay NULL."""
    raw = event_dict.get("raw_message") or ""
    if len(raw) > 8000:
        raw = raw[:8000]
    return (
        event_dict["event_id"],
        event_dict["timestamp"],
        event_dict["source_host"],
        event_dict["os_type"],
        event_dict["event_type"],
        event_dict["severity"],
        event_dict["source_ip"],
        event_dict["user"],
        raw,
        event_dict.get("client_id") or DEFAULT_CLIENT_ID,
        event_dict.get("site_id") or DEFAULT_SITE_ID,
        event_dict.get("dest_ip"),
        _optional_port(event_dict.get("dest_port")),
        event_dict.get("protocol"),
        event_dict.get("action"),
        event_dict.get("signature"),
        event_dict.get("category"),
    )


_LOG_INSERT = """
    INSERT INTO logs (
        event_id, timestamp, source_host, os_type, event_type,
        severity, source_ip, "user", raw_message, client_id, site_id,
        dest_ip, dest_port, protocol, action, signature, category
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (event_id) DO NOTHING
"""


def insert_event(event_dict: dict) -> bool:
    """Insert a single event into the database."""
    try:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute(_LOG_INSERT, _log_values(event_dict))
        inserted = cursor.rowcount == 1

        conn.commit()
        return_conn(conn)
        return inserted
    except Exception as e:
        print(f"Error inserting event: {e}")
        conn.rollback()
        return_conn(conn)
        return False

def insert_events_batch(events: list[dict]) -> tuple[int, int]:
    """Insert multiple events in one transaction.

    Duplicates use ON CONFLICT DO NOTHING so one repeat does not abort
    the rest of the batch (Postgres would otherwise cancel the transaction).
    """
    if not events:
        return (0, 0)
    try:
        conn = get_conn()
        cursor = conn.cursor()

        inserted = 0
        skipped = 0

        for event_dict in events:
            cursor.execute(_LOG_INSERT, _log_values(event_dict))
            if cursor.rowcount == 1:
                inserted += 1
            else:
                skipped += 1

        conn.commit()
        return_conn(conn)
        return (inserted, skipped)
    except Exception as e:
        print(f"Error inserting batch: {e}")
        conn.rollback()
        return_conn(conn)
        return (0, len(events))

def get_all_events(limit: int = 1000) -> list[dict]:
    """Get recent events from the database."""
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)

        cursor.execute("""
            SELECT * FROM logs
            ORDER BY timestamp DESC
            LIMIT %s
        """, (limit,))

        rows = cursor.fetchall()
        return_conn(conn)

        return [dict(row) for row in rows]
    except Exception as e:
        print(f"Error retrieving events: {e}")
        return_conn(conn)
        return []


def get_events_since(seconds: int, severity_min: int = None) -> list[dict]:
    """Events inserted in the last `seconds`, oldest first.

    Uses created_at (a real timestamp) so a burst is not cut off by LIMIT.
    """
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        query = """
            SELECT * FROM logs
            WHERE created_at > NOW() - (%s * INTERVAL '1 second')
        """
        params = [int(seconds)]
        if severity_min is not None:
            query += " AND severity >= %s"
            params.append(int(severity_min))
        query += " ORDER BY created_at ASC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return_conn(conn)
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"Error retrieving recent events: {e}")
        if conn:
            return_conn(conn)
        return []

def get_events_by_filter(os_type: str = None, severity: int = None,
                         event_type: str = None, limit: int = 1000,
                         severity_min: int = None, source_ip: str = None,
                         user: str = None, source_host: str = None,
                         raw_message: str = None, start_date: str = None,
                         end_date: str = None, offset: int = 0,
                         client_id: str = None, site_id: str = None) -> dict:
    """Get events with optional filters and pagination.

    Args:
        os_type: Filter by OS type (exact match)
        severity: Filter by exact severity level
        severity_min: Filter by minimum severity level
        event_type: Filter by event type (exact match)
        source_ip: Filter by source IP (exact match)
        user: Filter by username (case-insensitive partial match)
        source_host: Filter by source hostname (exact match)
        raw_message: Filter by raw message content (case-insensitive)
        start_date: Filter events on/after this date (ISO format: YYYY-MM-DD)
        end_date: Filter events on/before this date (ISO format: YYYY-MM-DD)
        limit: Maximum number of events to return (default 1000)
        offset: Number of events to skip for pagination (default 0)

    Returns:
        Dictionary with 'events' list, 'total_count', 'offset', and 'limit'
    """
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)

        query = "SELECT * FROM logs WHERE 1=1"
        params = []

        if os_type:
            query += " AND os_type = %s"
            params.append(os_type)
        if severity is not None:
            query += " AND severity = %s"
            params.append(severity)
        if severity_min is not None:
            query += " AND severity >= %s"
            params.append(severity_min)
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
        if source_ip:
            query += " AND source_ip = %s"
            params.append(source_ip)
        if user:
            query += " AND LOWER(\"user\") LIKE %s"
            params.append(f"%{user.lower()}%")
        if source_host:
            query += " AND source_host = %s"
            params.append(source_host)
        if raw_message:
            query += " AND LOWER(raw_message) LIKE %s"
            params.append(f"%{raw_message.lower()}%")
        if start_date:
            query += " AND timestamp::date >= %s"
            params.append(start_date)
        if end_date:
            query += " AND timestamp::date <= %s"
            params.append(end_date)
        if client_id:
            query += " AND client_id = %s"
            params.append(client_id)
        if site_id:
            query += " AND site_id = %s"
            params.append(site_id)

        # Get total count before pagination
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Add ordering and pagination
        query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
        params.append(limit)
        params.append(offset)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        return_conn(conn)

        return {
            'events': [dict(row) for row in rows],
            'total_count': total_count,
            'offset': offset,
            'limit': limit
        }
    except Exception as e:
        print(f"Error retrieving filtered events: {e}")
        return_conn(conn)
        return {'events': [], 'total_count': 0, 'offset': offset, 'limit': limit}

def _scope_sql(client_id: str = None, site_id: str = None) -> tuple[str, list]:
    clause = ""
    params = []
    if client_id:
        clause += " AND client_id = %s"
        params.append(client_id)
    if site_id:
        clause += " AND site_id = %s"
        params.append(site_id)
    return clause, params


def get_metrics_24h(client_id: str = None, site_id: str = None) -> dict:
    """Get metrics for the last 24 hours."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        scope, scope_params = _scope_sql(client_id, site_id)

        cursor.execute(f"""
            SELECT COUNT(*) as count FROM logs
            WHERE timestamp::timestamp >= NOW() - INTERVAL '24 hours'
            {scope}
        """, scope_params)
        total_alerts = cursor.fetchone()[0]

        cursor.execute(f"""
            SELECT os_type, COUNT(*) as count FROM logs
            WHERE timestamp::timestamp >= NOW() - INTERVAL '24 hours'
            {scope}
            GROUP BY os_type
        """, scope_params)
        threats_by_os = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(f"""
            SELECT raw_message, COUNT(*) as count FROM logs
            WHERE event_type = 'DNS_BLOCK'
            AND timestamp::timestamp >= NOW() - INTERVAL '24 hours'
            {scope}
            GROUP BY raw_message
            ORDER BY count DESC
            LIMIT 1
        """, scope_params)
        result = cursor.fetchone()
        most_blocked_domain = result[0] if result else None

        return_conn(conn)

        return {
            "total_alerts_24h": total_alerts,
            "threats_by_os": threats_by_os,
            "most_blocked_domain": most_blocked_domain
        }
    except Exception as e:
        print(f"Error calculating metrics: {e}")
        return_conn(conn)
        return {
            "total_alerts_24h": 0,
            "threats_by_os": {},
            "most_blocked_domain": None
        }

def get_top_attacking_ips(limit: int = 10, client_id: str = None, site_id: str = None) -> list[tuple[str, int]]:
    """Get top attacking IPs by frequency."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        scope, scope_params = _scope_sql(client_id, site_id)

        cursor.execute(f"""
            SELECT source_ip, COUNT(*) as count FROM logs
            WHERE source_ip != 'N/A'
            {scope}
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT %s
        """, (*scope_params, limit))

        results = cursor.fetchall()
        return_conn(conn)

        return results
    except Exception as e:
        print(f"Error getting top attacking IPs: {e}")
        return_conn(conn)
        return []

def get_events_per_minute(hours: int = 24, client_id: str = None, site_id: str = None) -> list[dict]:
    """Get event count per minute for the last N hours."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        scope, scope_params = _scope_sql(client_id, site_id)
        hours = max(1, int(hours))

        cursor.execute(f"""
            SELECT
                TO_CHAR(timestamp::timestamp, 'YYYY-MM-DD HH24:MI') as minute,
                os_type,
                COUNT(*) as count
            FROM logs
            WHERE timestamp::timestamp >= NOW() - (%s * INTERVAL '1 hour')
            {scope}
            GROUP BY minute, os_type
            ORDER BY minute
        """, (hours, *scope_params))

        rows = cursor.fetchall()
        return_conn(conn)

        return [{"minute": row[0], "os_type": row[1], "count": row[2]} for row in rows]
    except Exception as e:
        print(f"Error getting events per minute: {e}")
        return_conn(conn)
        return []

def record_heartbeat(source_host: str, os_type: str, client_id: str = None, site_id: str = None) -> bool:
    """Record a heartbeat from an agent."""
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # Use Python generated UTC timestamp for consistency with logs
        current_time = datetime.utcnow().isoformat() + "Z"
        cid = client_id or DEFAULT_CLIENT_ID
        sid = site_id or DEFAULT_SITE_ID

        cursor.execute("""
            INSERT INTO heartbeats (source_host, os_type, last_seen, updated_at, client_id, site_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (client_id, source_host) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                updated_at = EXCLUDED.updated_at,
                os_type = EXCLUDED.os_type,
                site_id = EXCLUDED.site_id
        """, (source_host, os_type, current_time, current_time, cid, sid))

        # Host is back. The next outage must be able to alert again.
        cursor.execute(
            "DELETE FROM alert_history WHERE event_id = %s AND alert_type = %s",
            (f"host-down-{source_host}", "host_down"),
        )

        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error recording heartbeat: {e}")
        conn.rollback()
        return_conn(conn)
        return False

def _aware(value):
    """Parse a stored timestamp into UTC."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value[:-1] if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        value = parsed
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _duration_phrase(delta: timedelta) -> str:
    minutes = max(int(delta.total_seconds()), 0) // 60
    if minutes < 120:
        n = max(minutes, 1)
        unit = "minute" if n == 1 else "minutes"
        return f"{n} {unit}"
    hours = minutes // 60
    if hours < 48:
        unit = "hour" if hours == 1 else "hours"
        return f"{hours} {unit}"
    days = hours // 24
    unit = "day" if days == 1 else "days"
    return f"{days} {unit}"


def _snippet(text: str, limit: int = 140) -> str:
    collapsed = " ".join((text or "").split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def _disk_percent(disk_info):
    if isinstance(disk_info, str):
        try:
            disk_info = json.loads(disk_info)
        except json.JSONDecodeError:
            return None
    if not isinstance(disk_info, list):
        return None
    percents = []
    for item in disk_info:
        if isinstance(item, dict) and item.get("percent") is not None:
            try:
                percents.append(float(item["percent"]))
            except (TypeError, ValueError):
                continue
    return max(percents) if percents else None


def _num(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def describe_offline(last_seen, from_heartbeat, last_event, last_status, now=None) -> str:
    """Plain reason a host is on the offline list."""
    now = now or datetime.now(timezone.utc)
    seen = _aware(last_seen)
    if seen is None:
        lead = "Last check-in time could not be read."
    else:
        phrase = _duration_phrase(now - seen)
        if from_heartbeat:
            lead = f"No heartbeat for {phrase}."
        else:
            lead = f"No agent heartbeat. Last log was {phrase} ago."
    parts = [lead]
    if last_event and last_event.get("event_type"):
        snippet = _snippet(last_event.get("raw_message") or "")
        event_bit = (
            f"Last event: {last_event['event_type']} "
            f"(severity {last_event.get('severity')})"
        )
        if snippet:
            event_bit += f" — {snippet}"
        parts.append(event_bit + ".")
    else:
        parts.append("No events stored for this system.")
    if last_status:
        bits = []
        if last_status.get("cpu_usage") is not None:
            bits.append(f"CPU {float(last_status['cpu_usage']):.0f}%")
        if last_status.get("memory_percent") is not None:
            bits.append(f"memory {float(last_status['memory_percent']):.0f}%")
        if last_status.get("disk_percent") is not None:
            bits.append(f"disk {float(last_status['disk_percent']):.0f}%")
        if bits:
            parts.append("Last resources: " + ", ".join(bits) + ".")
        else:
            parts.append("A resource snapshot was stored, but it had no CPU, memory, or disk reading.")
    else:
        parts.append("No resource snapshot was stored.")
    return " ".join(parts)


def _attach_offline_context(hosts: list) -> None:
    """Add last event, last resource snapshot, and a readable offline reason."""
    if not hosts:
        return
    pairs = []
    for host in hosts:
        name = host.get("source_host") or host.get("hostname")
        client_id = host.get("client_id") or DEFAULT_CLIENT_ID
        if name:
            pairs.append((name, client_id))
    events = {}
    statuses = {}
    if pairs:
        conn = get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT DISTINCT ON (source_host, client_id)
                    source_host, client_id, event_type, severity, timestamp, raw_message
                FROM logs
                WHERE (source_host, client_id) IN %s
                ORDER BY source_host, client_id, timestamp DESC
                """,
                (tuple(pairs),),
            )
            for row in cursor.fetchall():
                events[(row[0], row[1])] = {
                    "event_type": row[2],
                    "severity": row[3],
                    "timestamp": row[4],
                    "raw_message": _snippet(row[5] or "", 240),
                }
            cursor.execute(
                """
                SELECT DISTINCT ON (source_host, client_id)
                    source_host, client_id, cpu_usage, memory_percent, disk_info,
                    last_updated, os_details
                FROM system_status
                WHERE (source_host, client_id) IN %s
                ORDER BY source_host, client_id, last_updated DESC
                """,
                (tuple(pairs),),
            )
            for row in cursor.fetchall():
                updated = row[5]
                if isinstance(updated, datetime):
                    aware = _aware(updated)
                    updated = aware.isoformat().replace("+00:00", "Z") if aware else str(row[5])
                statuses[(row[0], row[1])] = {
                    "cpu_usage": _num(row[2]),
                    "memory_percent": _num(row[3]),
                    "disk_percent": _disk_percent(row[4]),
                    "last_updated": updated,
                    "os_details": row[6],
                }
        finally:
            return_conn(conn)
    now = datetime.now(timezone.utc)
    for host in hosts:
        key = (
            host.get("source_host") or host.get("hostname"),
            host.get("client_id") or DEFAULT_CLIENT_ID,
        )
        last_event = events.get(key)
        last_status = statuses.get(key)
        host["last_event"] = last_event
        host["last_status"] = last_status
        host["offline_reason"] = describe_offline(
            host.get("last_seen"),
            bool(host.get("from_heartbeat", True)),
            last_event,
            last_status,
            now=now,
        )


def get_host_status(inactive_threshold_minutes: int = 5, client_id: str = None, site_id: str = None) -> dict:
    """Get status of all hosts (active/inactive)."""
    try:
        conn = get_conn()
        cursor = conn.cursor()

        hb_clauses = []
        log_clauses = []
        hb_params = []
        log_params = []
        # Syslog devices, Action1 inventory, and docker-update logs are not
        # agents. A quiet gateway, an Action1 computer, or a docker server
        # must not become a host that pages Telegram when it goes quiet.
        hb_clauses.append("h.os_type <> 'UNIFI'")
        log_clauses.append("l.os_type <> 'UNIFI'")
        hb_clauses.append("h.os_type <> 'ACTION1'")
        log_clauses.append("l.os_type <> 'ACTION1'")
        hb_clauses.append("h.os_type <> 'DOCKER'")
        log_clauses.append("l.os_type <> 'DOCKER'")
        if client_id:
            hb_clauses.append("h.client_id = %s")
            log_clauses.append("l.client_id = %s")
            hb_params.append(client_id)
            log_params.append(client_id)
        if site_id:
            hb_clauses.append("h.site_id = %s")
            log_clauses.append("l.site_id = %s")
            hb_params.append(site_id)
            log_params.append(site_id)
        # Heartbeat placeholders come first in the UNION, then the log ones.
        params = hb_params + log_params
        hb_where = ("WHERE " + " AND ".join(hb_clauses)) if hb_clauses else ""
        log_and = ("AND " + " AND ".join(log_clauses)) if log_clauses else ""

        cursor.execute(f"""
            SELECT
                source_host,
                os_type,
                last_seen,
                total_events,
                client_id,
                site_id,
                from_heartbeat
            FROM (
                SELECT
                    h.source_host,
                    h.os_type,
                    h.last_seen,
                    COALESCE((SELECT COUNT(*) FROM logs WHERE source_host = h.source_host
                              AND logs.client_id = h.client_id), 0) as total_events,
                    h.client_id,
                    h.site_id,
                    TRUE as from_heartbeat
                FROM heartbeats h
                {hb_where}

                UNION

                SELECT
                    l.source_host,
                    l.os_type,
                    MAX(l.timestamp::timestamp) as last_seen,
                    COUNT(l.id) as total_events,
                    l.client_id,
                    l.site_id,
                    FALSE as from_heartbeat
                FROM logs l
                WHERE NOT EXISTS (
                    SELECT 1 FROM heartbeats h2
                    WHERE h2.source_host = l.source_host AND h2.client_id = l.client_id
                )
                {log_and}
                GROUP BY l.source_host, l.os_type, l.client_id, l.site_id
            ) combined
            ORDER BY last_seen DESC
        """, params or None)

        rows = cursor.fetchall()
        return_conn(conn)

        # Calculate threshold time
        threshold_time = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)

        active_hosts = []
        inactive_hosts = []

        for row in rows:
            try:
                last_seen_str = row[2]

                # Parse the timestamp
                if isinstance(last_seen_str, str):
                    if "T" in last_seen_str:
                        if last_seen_str.endswith("Z"):
                            last_seen_str = last_seen_str[:-1]
                        last_seen_dt = datetime.fromisoformat(last_seen_str).replace(tzinfo=timezone.utc)
                    else:
                        last_seen_dt = datetime.fromisoformat(last_seen_str).replace(tzinfo=timezone.utc)
                else:
                    last_seen_dt = last_seen_str

                # Convert to ISO format with Z suffix for API response
                iso_timestamp = last_seen_dt.isoformat() + "Z"

                host_info = {
                    "hostname": row[0],
                    "source_host": row[0],
                    "os_type": row[1],
                    "last_seen": iso_timestamp,
                    "total_events": row[3],
                    "client_id": row[4] if len(row) > 4 else DEFAULT_CLIENT_ID,
                    "site_id": row[5] if len(row) > 5 else DEFAULT_SITE_ID,
                    "from_heartbeat": bool(row[6]) if len(row) > 6 else True,
                }

                if last_seen_dt >= threshold_time:
                    active_hosts.append(host_info)
                else:
                    inactive_hosts.append(host_info)
            except Exception as e:
                print(f"Error parsing timestamp for {row[0]}: {e}")
                host_info = {
                    "hostname": row[0],
                    "source_host": row[0],
                    "os_type": row[1],
                    "last_seen": str(row[2]),
                    "total_events": row[3],
                    "client_id": row[4] if len(row) > 4 else DEFAULT_CLIENT_ID,
                    "site_id": row[5] if len(row) > 5 else DEFAULT_SITE_ID,
                    "from_heartbeat": bool(row[6]) if len(row) > 6 else True,
                    "offline_reason": "Last check-in time could not be read.",
                }
                inactive_hosts.append(host_info)

        try:
            _attach_offline_context(inactive_hosts)
        except Exception as exc:
            print(f"Error describing offline hosts: {exc}")

        needs_agent = []
        try:
            needs_agent = _action1_hosts_needing_agent(
                active_hosts, inactive_hosts, client_id, site_id,
            )
        except Exception as exc:
            print(f"Error attaching Action1 hosts: {exc}")

        return {
            "active": active_hosts,
            "inactive": inactive_hosts,
            "needs_agent": needs_agent,
            "threshold_minutes": inactive_threshold_minutes
        }
    except Exception as e:
        print(f"Error getting host status: {e}")
        return_conn(conn)
        return {
            "active": [],
            "inactive": [],
            "needs_agent": [],
            "threshold_minutes": inactive_threshold_minutes,
        }


def _action1_hosts_needing_agent(active_hosts: list, inactive_hosts: list,
                                 client_id: str = None, site_id: str = None) -> list:
    """Action1 computers with no matching Heimdall agent check-in.

    These are hosts for the Systems page. They are not inactive agents, so
    they must not be returned in the list that pages Telegram.
    """
    from .action1_store import AGENT_INSTALLED, LABEL_INSTALLED, host_match_key, list_endpoints

    endpoints = list_endpoints(client_id)
    by_key = {}
    for row in endpoints:
        key = host_match_key(row.get("name") or "")
        if key:
            by_key[(row.get("client_id"), key)] = row
    for host in list(active_hosts) + list(inactive_hosts):
        key = host_match_key(host.get("hostname") or host.get("source_host") or "")
        row = by_key.get((host.get("client_id"), key)) if key else None
        if row and row.get("heimdall_agent") == AGENT_INSTALLED:
            host["heimdall_agent"] = AGENT_INSTALLED
            host["agent_label"] = LABEL_INSTALLED
    needs = []
    for row in endpoints:
        if row.get("heimdall_agent") != "needs_install":
            continue
        if site_id and (row.get("site_id") or "") != site_id:
            continue
        name = row.get("name") or row.get("endpoint_id") or ""
        needs.append({
            "hostname": name,
            "source_host": name,
            "os_type": row.get("os_name") or row.get("platform") or "ACTION1",
            "last_seen": row.get("last_seen") or "",
            "total_events": 0,
            "client_id": row.get("client_id"),
            "site_id": row.get("site_id") or "",
            "from_heartbeat": False,
            "heimdall_agent": "needs_install",
            "agent_label": row.get("heimdall_agent_label") or "Heimdall agent needs install",
            "action1_status": row.get("status") or "",
            "action1_org_id": row.get("action1_org_id") or "",
            "endpoint_id": row.get("endpoint_id") or "",
        })
    return needs

def get_open_docker_run_events(hours: int = 6, severity_min: int = 4) -> list:
    """Unsent docker CVE and update rows from the last few hours.

    Includes the low-severity line that closes a run, so a finished update
    can be described once instead of once per log line.
    """
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute("""
            SELECT l.*
            FROM logs l
            LEFT JOIN alert_history a
              ON a.event_id = l.event_id AND a.alert_type = 'critical'
            WHERE l.os_type = 'DOCKER'
              AND l.category IN ('docker-cve', 'docker-update')
              AND l.created_at > NOW() - (%s * INTERVAL '1 hour')
              AND a.event_id IS NULL
              AND (
                l.severity >= %s
                OR l.raw_message ~ '^(===== done failures=|updater exited|updater finished|no security update needed|baseline refreshed)'
              )
            ORDER BY l.timestamp ASC, l.created_at ASC
        """, (int(hours), int(severity_min)))
        rows = cursor.fetchall()
        return_conn(conn)
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"Error retrieving open docker run events: {e}")
        if conn:
            return_conn(conn)
        return []


def check_alert_sent(event_id: str, alert_type: str = "critical") -> bool:
    """Check if an alert has already been sent for this event."""
    try:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id FROM alert_history
            WHERE event_id = %s AND alert_type = %s
            LIMIT 1
        """, (event_id, alert_type))

        result = cursor.fetchone()
        return_conn(conn)
        return result is not None
    except Exception as e:
        print(f"Error checking alert history: {e}")
        return_conn(conn)
        return False

def record_alert_sent(event_id: str, alert_type: str = "critical") -> bool:
    """Record that an alert has been sent for this event."""
    try:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO alert_history (event_id, alert_type)
            VALUES (%s, %s)
            ON CONFLICT (event_id, alert_type) DO NOTHING
        """, (event_id, alert_type))

        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error recording alert history: {e}")
        conn.rollback()
        return_conn(conn)
        return False

def remove_monitored_host(source_host: str, client_id: str = None) -> dict:
    """Take an endpoint off the host list.

    Deletes the heartbeat, logs, resource snapshot, metrics, and placement for
    this hostname. alert_history is left alone so a leftover row cannot page
    Telegram as a new host-down alert. A client_id limits the delete to that
    organization.
    """
    source_host = (source_host or "").strip()
    if client_id is not None:
        client_id = client_id.strip() or None
    counts = {
        "heartbeats": 0,
        "logs": 0,
        "system_status": 0,
        "host_metrics": 0,
        "endpoint_placements": 0,
    }
    if not source_host:
        return {"removed": False, **counts}

    conn = get_conn()
    try:
        cursor = conn.cursor()
        for table in ("heartbeats", "logs", "system_status", "host_metrics"):
            if client_id:
                cursor.execute(
                    f"DELETE FROM {table} WHERE source_host = %s AND client_id = %s",
                    (source_host, client_id),
                )
            else:
                cursor.execute(
                    f"DELETE FROM {table} WHERE source_host = %s",
                    (source_host,),
                )
            counts[table] = cursor.rowcount
        if client_id:
            cursor.execute(
                """
                DELETE FROM endpoint_placements
                WHERE source_host = %s AND (client_id = %s OR origin_client_id = %s)
                """,
                (source_host, client_id, client_id),
            )
        else:
            cursor.execute(
                "DELETE FROM endpoint_placements WHERE source_host = %s",
                (source_host,),
            )
        counts["endpoint_placements"] = cursor.rowcount
        conn.commit()
        return_conn(conn)
        return {"removed": any(counts.values()), **counts}
    except Exception as e:
        print(f"Error removing host {source_host}: {e}")
        conn.rollback()
        return_conn(conn)
        raise


def delete_host_events(source_host: str) -> bool:
    """Remove a hostname from every organization. Kept for older callers."""
    try:
        remove_monitored_host(source_host, client_id=None)
        return True
    except Exception as e:
        print(f"Error deleting host events: {e}")
        return False

def get_config(key: str, default: str = None) -> str:
    """Get a configuration value from the database."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        
        cursor.execute("SELECT value FROM config WHERE key = %s", (key,))
        result = cursor.fetchone()
        
        return_conn(conn)
        
        if result:
            return result[0]
        return default
    except Exception as e:
        print(f"Error getting config '{key}': {e}")
        if conn:
            return_conn(conn)
        return default

def set_config(key: str, value: str) -> bool:
    """Set a configuration value in the database."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO config (key, value, updated_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = EXCLUDED.updated_at
        """, (key, str(value)))
        
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error setting config '{key}': {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False

def upsert_system_status(status: dict) -> bool:
    """Insert or update system status for a host."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        
        # Helper to dump dicts/lists to JSON string for Postgres
        import json
        
        cid = status.get("client_id") or DEFAULT_CLIENT_ID
        sid = status.get("site_id") or DEFAULT_SITE_ID
        cursor.execute("""
            INSERT INTO system_status (
                source_host, os_type, os_details,
                cpu_usage, cpu_count,
                memory_total, memory_used, memory_percent,
                disk_info, network_info, top_processes,
                boot_time, last_updated, client_id, site_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s)
            ON CONFLICT (client_id, source_host) DO UPDATE SET
                os_type = EXCLUDED.os_type,
                os_details = EXCLUDED.os_details,
                cpu_usage = EXCLUDED.cpu_usage,
                cpu_count = EXCLUDED.cpu_count,
                memory_total = EXCLUDED.memory_total,
                memory_used = EXCLUDED.memory_used,
                memory_percent = EXCLUDED.memory_percent,
                disk_info = EXCLUDED.disk_info,
                network_info = EXCLUDED.network_info,
                top_processes = EXCLUDED.top_processes,
                boot_time = EXCLUDED.boot_time,
                last_updated = CURRENT_TIMESTAMP,
                site_id = EXCLUDED.site_id
        """, (
            status["source_host"], status["os_type"], status["os_details"],
            status["cpu_usage"], status["cpu_count"],
            status["memory_total"], status["memory_used"], status["memory_percent"],
            json.dumps(status.get("disk_info") or []),
            json.dumps(status.get("network_info") or []),
            json.dumps(status.get("top_processes") or []),
            status["boot_time"],
            cid,
            sid,
        ))
        
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error upserting system status: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False

def get_system_status(source_host: str, client_id: str = None) -> dict:
    """Get the latest system status for a host."""
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        
        if client_id:
            cursor.execute("""
                SELECT * FROM system_status WHERE source_host = %s AND client_id = %s
            """, (source_host, client_id))
        else:
            cursor.execute("""
                SELECT * FROM system_status WHERE source_host = %s
                ORDER BY last_updated DESC LIMIT 1
            """, (source_host,))
        
        result = cursor.fetchone()
        return_conn(conn)
        
        if result:
            return dict(result)
        return None
    except Exception as e:
        print(f"Error getting system status: {e}")
        if conn:
            return_conn(conn)
        return None

def _init_metrics_and_tenancy(cursor):
    """Create metric/tenant tables and add client_id columns to existing tables."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            telegram_chat_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES clients(id),
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_placements (
            source_host TEXT NOT NULL,
            origin_client_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            site_id TEXT NOT NULL,
            PRIMARY KEY (origin_client_id, source_host)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_hash TEXT PRIMARY KEY,
            key_prefix TEXT,
            role TEXT NOT NULL,
            client_id TEXT NOT NULL,
            site_id TEXT,
            label TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS host_metrics (
            id BIGSERIAL PRIMARY KEY,
            time TIMESTAMPTZ NOT NULL,
            source_host TEXT NOT NULL,
            client_id TEXT NOT NULL DEFAULT 'default',
            site_id TEXT NOT NULL DEFAULT 'default',
            metric TEXT NOT NULL,
            value DOUBLE PRECISION NOT NULL,
            labels JSONB NOT NULL DEFAULT '{}'::jsonb
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_host_metrics_host_metric_time
        ON host_metrics (source_host, metric, time DESC)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_host_metrics_client_time
        ON host_metrics (client_id, time DESC)
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            metric TEXT NOT NULL,
            op TEXT NOT NULL DEFAULT '>',
            threshold DOUBLE PRECISION NOT NULL,
            duration_seconds INTEGER NOT NULL DEFAULT 600,
            severity INTEGER NOT NULL DEFAULT 4,
            hysteresis DOUBLE PRECISION NOT NULL DEFAULT 5,
            enabled BOOLEAN NOT NULL DEFAULT TRUE
        )
    """)

    for table in ("logs", "heartbeats", "system_status"):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS client_id TEXT NOT NULL DEFAULT 'default'")
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS site_id TEXT NOT NULL DEFAULT 'default'")

    for column, coltype in (
        ("dest_ip", "TEXT"),
        ("dest_port", "INTEGER"),
        ("protocol", "TEXT"),
        ("action", "TEXT"),
        ("signature", "TEXT"),
        ("category", "TEXT"),
    ):
        cursor.execute(f"ALTER TABLE logs ADD COLUMN IF NOT EXISTS {column} {coltype}")

    _rekey_unique(cursor, "heartbeats")
    _rekey_unique(cursor, "system_status")

    cursor.execute("ALTER TABLE clients ADD COLUMN IF NOT EXISTS slug TEXT")
    cursor.execute("ALTER TABLE clients ADD COLUMN IF NOT EXISTS accent TEXT")
    cursor.execute("""
        INSERT INTO clients (id, name, slug) VALUES ('default', 'Default', 'default')
        ON CONFLICT (id) DO NOTHING
    """)
    cursor.execute("UPDATE clients SET slug = id WHERE slug IS NULL OR slug = ''")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS clients_slug_uidx ON clients (slug)")
    cursor.execute("""
        INSERT INTO sites (id, client_id, name) VALUES ('default', 'default', 'default')
        ON CONFLICT (id) DO NOTHING
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS action1_links (
            action1_org_id TEXT PRIMARY KEY,
            action1_org_name TEXT NOT NULL DEFAULT '',
            client_id TEXT NOT NULL,
            site_id TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS action1_endpoints (
            action1_org_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            name TEXT,
            status TEXT,
            platform TEXT,
            os_name TEXT,
            address TEXT,
            external_address TEXT,
            user_name TEXT,
            last_seen TEXT,
            agent_version TEXT,
            missing_critical_updates INTEGER,
            missing_other_updates INTEGER,
            comment TEXT,
            synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (action1_org_id, endpoint_id)
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_action1_endpoints_client
        ON action1_endpoints (client_id)
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS action1_snapshots (
            kind TEXT NOT NULL,
            action1_org_id TEXT NOT NULL DEFAULT '',
            payload TEXT NOT NULL,
            synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (kind, action1_org_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS docker_servers (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            site_id TEXT NOT NULL,
            name TEXT NOT NULL,
            ssh_host TEXT NOT NULL,
            ssh_port INTEGER NOT NULL DEFAULT 22,
            ssh_user TEXT NOT NULL,
            log_dir TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_poll TIMESTAMP,
            last_ok TIMESTAMP,
            last_error TEXT
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_docker_servers_client
        ON docker_servers (client_id)
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS docker_log_cursors (
            server_id TEXT NOT NULL,
            basename TEXT NOT NULL,
            inode TEXT,
            file_offset BIGINT NOT NULL DEFAULT 0,
            pending TEXT NOT NULL DEFAULT '',
            bootstrapped BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (server_id, basename)
        )
    """)

    from .resource_alerts import DEFAULT_RULES
    for rule in DEFAULT_RULES:
        cursor.execute("""
            INSERT INTO alert_rules (id, name, metric, op, threshold, duration_seconds, severity, hysteresis, enabled)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (
            rule["id"], rule["name"], rule["metric"], rule["op"], rule["threshold"],
            rule["duration_seconds"], rule["severity"], rule["hysteresis"], rule["enabled"],
        ))


def _rekey_unique(cursor, table: str):
    """Replace UNIQUE(source_host) with UNIQUE(client_id, source_host)."""
    cursor.execute("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = %s::regclass AND contype = 'u'
    """, (table,))
    for (conname,) in cursor.fetchall():
        cursor.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = %s AND conrelid = %s::regclass",
            (conname, table),
        )
        row = cursor.fetchone()
        if not row:
            continue
        definition = row[0].replace(" ", "").lower()
        if "source_host" in definition and "client_id" not in definition:
            cursor.execute(f'ALTER TABLE {table} DROP CONSTRAINT IF EXISTS "{conname}"')
    cursor.execute(f"""
        CREATE UNIQUE INDEX IF NOT EXISTS {table}_client_host_uidx
        ON {table} (client_id, source_host)
    """)


def insert_metric_samples(samples: list[dict], client_id: str = None, site_id: str = None) -> int:
    """Append metric samples. Returns number inserted."""
    if not samples:
        return 0
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        inserted = 0
        for sample in samples:
            ts = sample.get("time")
            cursor.execute("""
                INSERT INTO host_metrics (time, source_host, client_id, site_id, metric, value, labels)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                ts,
                sample["source_host"],
                sample.get("client_id") or client_id or DEFAULT_CLIENT_ID,
                sample.get("site_id") or site_id or DEFAULT_SITE_ID,
                sample["metric"],
                float(sample["value"]),
                json.dumps(sample.get("labels") or {}),
            ))
            inserted += 1
        conn.commit()
        return_conn(conn)
        return inserted
    except Exception as e:
        print(f"Error inserting metric samples: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return 0


def get_metric_rows(source_host: str = None, metric: str = None, client_id: str = None,
                    start: str = None, end: str = None, limit: int = 20000,
                    site_id: str = None) -> list[dict]:
    """Fetch raw host_metrics rows in a time window."""
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        query = "SELECT time, source_host, client_id, site_id, metric, value, labels FROM host_metrics WHERE 1=1"
        params = []
        if source_host:
            query += " AND source_host = %s"
            params.append(source_host)
        if metric:
            query += " AND metric = %s"
            params.append(metric)
        if client_id:
            query += " AND client_id = %s"
            params.append(client_id)
        if site_id:
            query += " AND site_id = %s"
            params.append(site_id)
        if start:
            query += " AND time >= %s"
            params.append(start)
        if end:
            query += " AND time <= %s"
            params.append(end)
        query += " ORDER BY time ASC LIMIT %s"
        params.append(limit)
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        return_conn(conn)
        for row in rows:
            ts = row.get("time")
            if hasattr(ts, "isoformat"):
                row["time"] = ts.isoformat()
            if row.get("labels") is None:
                row["labels"] = {}
        return rows
    except Exception as e:
        print(f"Error fetching metric rows: {e}")
        if conn:
            return_conn(conn)
        return []


def query_host_metrics(source_host: str = None, metric: str = None, client_id: str = None,
                       start: str = None, end: str = None, step_seconds: int = 0,
                       site_id: str = None) -> list[dict]:
    """Filter + downsample host metrics using the shipped query_samples helper."""
    rows = get_metric_rows(source_host=source_host, metric=metric, client_id=client_id,
                           start=start, end=end, site_id=site_id)
    return bucket_query_samples(
        rows,
        source_host=source_host,
        metric=metric,
        client_id=client_id,
        start=start,
        end=end,
        step_seconds=step_seconds or 0,
    )


def get_all_system_status(client_id: str = None, site_id: str = None) -> list[dict]:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        query = "SELECT * FROM system_status WHERE 1=1"
        params = []
        if client_id:
            query += " AND client_id = %s"
            params.append(client_id)
        if site_id:
            query += " AND site_id = %s"
            params.append(site_id)
        query += " ORDER BY source_host"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        return_conn(conn)
        return rows
    except Exception as e:
        print(f"Error listing system status: {e}")
        if conn:
            return_conn(conn)
        return []


def lookup_api_key(key_hash: str) -> dict:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute("SELECT * FROM api_keys WHERE key_hash = %s", (key_hash,))
        row = cursor.fetchone()
        return_conn(conn)
        return dict(row) if row else None
    except Exception as e:
        print(f"Error looking up API key: {e}")
        if conn:
            return_conn(conn)
        return None


def create_client(client_id: str, name: str, telegram_chat_id: str = None, site_name: str = "default") -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO clients (id, name, telegram_chat_id, slug) VALUES (%s, %s, %s, %s)",
            (client_id, name, telegram_chat_id, client_id),
        )
        site_id = f"{client_id}-{site_name}"
        cursor.execute(
            "INSERT INTO sites (id, client_id, name) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (site_id, client_id, site_name),
        )
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error creating client: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def insert_api_key(key_hash: str, key_prefix: str, role: str, client_id: str,
                   site_id: str = None, label: str = None) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO api_keys (key_hash, key_prefix, role, client_id, site_id, label)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (key_hash, key_prefix, role, client_id, site_id, label))
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error inserting API key: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def _client_row_with_sites(cursor, client_id: str = None) -> list[dict]:
    query = """
        SELECT c.id, c.name, c.telegram_chat_id, c.created_at, c.slug, c.accent,
               COALESCE((
                   SELECT json_agg(json_build_object('id', s.id, 'name', s.name) ORDER BY s.name)
                   FROM sites s WHERE s.client_id = c.id
               ), '[]'::json) AS sites,
               COALESCE((SELECT COUNT(*) FROM heartbeats h WHERE h.client_id = c.id), 0)
               + COALESCE((
                   SELECT COUNT(*) FROM action1_endpoints e
                   WHERE e.client_id = c.id
                     AND btrim(COALESCE(e.name, '')) <> ''
                     AND NOT EXISTS (
                       SELECT 1 FROM heartbeats h
                       WHERE h.client_id = e.client_id
                         AND h.os_type <> 'UNIFI'
                         AND h.os_type <> 'ACTION1'
                         AND lower(split_part(regexp_replace(COALESCE(h.source_host, ''), '\\.local$', '', 'i'), '.', 1)) <> ''
                         AND lower(split_part(regexp_replace(COALESCE(h.source_host, ''), '\\.local$', '', 'i'), '.', 1))
                           = lower(split_part(regexp_replace(COALESCE(e.name, ''), '\\.local$', '', 'i'), '.', 1))
                     )
               ), 0)
               + COALESCE((SELECT COUNT(*) FROM docker_servers d WHERE d.client_id = c.id), 0) AS host_count,
               COALESCE((
                   SELECT k.key_prefix FROM api_keys k
                   WHERE k.client_id = c.id AND k.role = 'agent'
                   ORDER BY k.created_at DESC LIMIT 1
               ), '') AS key_prefix
        FROM clients c
    """
    params = []
    if client_id:
        query += " WHERE c.id = %s OR c.slug = %s"
        params.extend([client_id, client_id])
    query += " ORDER BY c.name"
    cursor.execute(query, params)
    rows = []
    for r in cursor.fetchall():
        item = dict(r)
        sites = item.get("sites") or []
        if isinstance(sites, str):
            try:
                sites = json.loads(sites)
            except Exception:
                sites = []
        item["sites"] = sites
        if item.get("created_at") and hasattr(item["created_at"], "isoformat"):
            item["created_at"] = item["created_at"].isoformat()
        from .tenancy import decorate_org
        rows.append(decorate_org(item))
    return rows


def list_clients() -> list[dict]:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        rows = _client_row_with_sites(cursor)
        return_conn(conn)
        return rows
    except Exception as e:
        print(f"Error listing clients: {e}")
        if conn:
            return_conn(conn)
        return []


def get_client(client_id: str) -> dict:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        rows = _client_row_with_sites(cursor, client_id)
        return_conn(conn)
        return rows[0] if rows else None
    except Exception as e:
        print(f"Error getting client: {e}")
        if conn:
            return_conn(conn)
        return None


def update_client(client_id: str, name: str = None, telegram_chat_id: str = None) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        sets = []
        params = []
        if name is not None:
            sets.append("name = %s")
            params.append(name)
        if telegram_chat_id is not None:
            sets.append("telegram_chat_id = %s")
            params.append(telegram_chat_id)
        if not sets:
            return_conn(conn)
            return True
        params.append(client_id)
        cursor.execute(f"UPDATE clients SET {', '.join(sets)} WHERE id = %s", params)
        conn.commit()
        ok = cursor.rowcount > 0
        return_conn(conn)
        return ok
    except Exception as e:
        print(f"Error updating client: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def delete_client(client_id: str) -> bool:
    """Remove a client, its sites, and API keys. Host rows keep client_id for history."""
    if client_id == DEFAULT_CLIENT_ID:
        return False
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM endpoint_placements WHERE client_id = %s OR origin_client_id = %s",
            (client_id, client_id),
        )
        cursor.execute(
            """
            DELETE FROM action1_snapshots
            WHERE action1_org_id IN (
                SELECT action1_org_id FROM action1_links WHERE client_id = %s
            )
            """,
            (client_id,),
        )
        cursor.execute("DELETE FROM action1_endpoints WHERE client_id = %s", (client_id,))
        cursor.execute("DELETE FROM action1_links WHERE client_id = %s", (client_id,))
        cursor.execute(
            """
            DELETE FROM docker_log_cursors
            WHERE server_id IN (SELECT id FROM docker_servers WHERE client_id = %s)
            """,
            (client_id,),
        )
        cursor.execute("DELETE FROM docker_servers WHERE client_id = %s", (client_id,))
        cursor.execute("DELETE FROM api_keys WHERE client_id = %s", (client_id,))
        cursor.execute("DELETE FROM sites WHERE client_id = %s", (client_id,))
        cursor.execute("DELETE FROM clients WHERE id = %s", (client_id,))
        conn.commit()
        ok = cursor.rowcount > 0
        return_conn(conn)
        return ok
    except Exception as e:
        print(f"Error deleting client: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def list_sites(client_id: str) -> list[dict]:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute(
            "SELECT id, client_id, name, created_at FROM sites WHERE client_id = %s ORDER BY name",
            (client_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        return_conn(conn)
        return rows
    except Exception as e:
        print(f"Error listing sites: {e}")
        if conn:
            return_conn(conn)
        return []


def create_site(site_id: str, client_id: str, name: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sites (id, client_id, name) VALUES (%s, %s, %s)",
            (site_id, client_id, name),
        )
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error creating site: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def update_site(site_id: str, name: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("UPDATE sites SET name = %s WHERE id = %s", (name, site_id))
        conn.commit()
        ok = cursor.rowcount > 0
        return_conn(conn)
        return ok
    except Exception as e:
        print(f"Error updating site: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def delete_site(site_id: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT client_id FROM sites WHERE id = %s", (site_id,))
        row = cursor.fetchone()
        if not row:
            return_conn(conn)
            return False
        cursor.execute("SELECT COUNT(*) FROM sites WHERE client_id = %s", (row[0],))
        if cursor.fetchone()[0] <= 1:
            return_conn(conn)
            return False
        cursor.execute("DELETE FROM sites WHERE id = %s", (site_id,))
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error deleting site: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def delete_api_keys_for_client(client_id: str) -> bool:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE client_id = %s", (client_id,))
        conn.commit()
        return_conn(conn)
        return True
    except Exception as e:
        print(f"Error deleting API keys: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return False


def get_site(site_id: str) -> dict:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute("SELECT * FROM sites WHERE id = %s", (site_id,))
        row = cursor.fetchone()
        return_conn(conn)
        return dict(row) if row else None
    except Exception as e:
        print(f"Error getting site: {e}")
        if conn:
            return_conn(conn)
        return None


def list_alert_rules() -> list[dict]:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        cursor.execute("SELECT * FROM alert_rules ORDER BY id")
        rows = [dict(r) for r in cursor.fetchall()]
        return_conn(conn)
        return rows
    except Exception as e:
        print(f"Error listing alert rules: {e}")
        if conn:
            return_conn(conn)
        return []


def purge_old_metrics(native_days: int = 14) -> int:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM host_metrics WHERE time < NOW() - (%s * INTERVAL '1 day')",
            (native_days,),
        )
        deleted = cursor.rowcount
        conn.commit()
        return_conn(conn)
        return deleted
    except Exception as e:
        print(f"Error purging metrics: {e}")
        if conn:
            conn.rollback()
            return_conn(conn)
        return 0


if __name__ == "__main__":
    init_database()

