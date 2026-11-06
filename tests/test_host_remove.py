#!/usr/bin/env python3
"""Removing an offline endpoint deletes the rows that keep it on the host list."""

import os
import uuid

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"
os.environ["SIEM_DB_HOST"] = "127.0.0.1"
os.environ["SIEM_DB_PORT"] = "55432"
os.environ["SIEM_DB_NAME"] = "heimdall"
os.environ["SIEM_DB_USER"] = "heimdall"
os.environ["SIEM_DB_PASSWORD"] = "heimdall"

import psycopg2
import unittest

from fastapi.testclient import TestClient

from core import server_api
from core.database_pg import init_database


def setUpModule():
    init_database()


def _counts(source_host, client_id):
    conn = psycopg2.connect(
        host="127.0.0.1",
        port=55432,
        dbname="heimdall",
        user="heimdall",
        password="heimdall",
    )
    cur = conn.cursor()
    found = {}
    for table in ("heartbeats", "logs", "system_status", "host_metrics"):
        cur.execute(
            f"SELECT COUNT(*) FROM {table} WHERE source_host = %s AND client_id = %s",
            (source_host, client_id),
        )
        found[table] = cur.fetchone()[0]
    cur.execute(
        "SELECT COUNT(*) FROM alert_history WHERE event_id = %s AND alert_type = 'host_down'",
        (f"host-down-{source_host}",),
    )
    found["alert_history"] = cur.fetchone()[0]
    conn.close()
    return found


class TestHostRemove(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(server_api.app)
        cls.op = {"api-key": "test-operator-key"}

    def _event(self, event_id, host, message):
        return {
            "event_id": event_id,
            "timestamp": "2026-10-12T00:00:00+00:00",
            "source_host": host,
            "os_type": "LINUX",
            "event_type": "LOGIN_FAIL",
            "severity": 2,
            "source_ip": "203.0.113.50",
            "user": "root",
            "raw_message": message,
        }

    def _status(self, host):
        return {
            "source_host": host,
            "os_type": "LINUX",
            "os_details": "test kernel",
            "cpu_usage": 41.2,
            "cpu_count": 2,
            "memory_total": 1000,
            "memory_used": 400,
            "memory_percent": 40.0,
            "disk_info": [{"mount": "/", "percent": 77.0}],
            "network_info": [],
            "top_processes": [],
            "boot_time": "2026-10-01T00:00:00Z",
            "timestamp": "2026-10-12T00:00:00Z",
        }

    def _names(self, payload):
        hosts = (payload.get("active_hosts") or []) + (payload.get("inactive_hosts") or [])
        return {h.get("hostname") or h.get("source_host") for h in hosts}

    def _backdate(self, host, client_id):
        conn = psycopg2.connect(
            host="127.0.0.1",
            port=55432,
            dbname="heimdall",
            user="heimdall",
            password="heimdall",
        )
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE heartbeats
            SET last_seen = NOW() - INTERVAL '5 days'
            WHERE source_host = %s AND client_id = %s
            """,
            (host, client_id),
        )
        cur.execute(
            """
            UPDATE system_status
            SET last_updated = NOW() - INTERVAL '5 days'
            WHERE source_host = %s AND client_id = %s
            """,
            (host, client_id),
        )
        cur.execute(
            """
            INSERT INTO alert_history (event_id, alert_type)
            VALUES (%s, 'host_down')
            ON CONFLICT (event_id, alert_type) DO NOTHING
            """,
            (f"host-down-{host}",),
        )
        conn.commit()
        conn.close()

    def test_remove_clears_heartbeat_and_explains_offline(self):
        suffix = uuid.uuid4().hex[:8]
        host = f"quiet-{suffix}"
        keeper = f"keeper-{suffix}"

        created_a = self.client.post(
            "/clients",
            json={"name": f"Quiet Org {suffix}", "site_name": "hq"},
            headers=self.op,
        )
        self.assertEqual(created_a.status_code, 200, created_a.text)
        org_a = created_a.json()["client_id"]
        key_a = created_a.json()["agent_api_key"]

        created_b = self.client.post(
            "/clients",
            json={"name": f"Other Org {suffix}", "site_name": "hq"},
            headers=self.op,
        )
        self.assertEqual(created_b.status_code, 200, created_b.text)
        org_b = created_b.json()["client_id"]
        key_b = created_b.json()["agent_api_key"]

        ingested = self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-a", host, "authentication failure on tty")]},
            headers={"api-key": key_a},
        )
        self.assertEqual(ingested.status_code, 200, ingested.text)
        kept = self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-k", keeper, "keeper still here")]},
            headers={"api-key": key_a},
        )
        self.assertEqual(kept.status_code, 200, kept.text)
        other = self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-b", host, "other org copy")]},
            headers={"api-key": key_b},
        )
        self.assertEqual(other.status_code, 200, other.text)
        status = self.client.post(
            "/system-status",
            json={"status": self._status(host)},
            headers={"api-key": key_a},
        )
        self.assertEqual(status.status_code, 200, status.text)

        self._backdate(host, org_a)

        listed = self.client.get("/hosts", params={"client_id": org_a}, headers=self.op)
        self.assertEqual(listed.status_code, 200, listed.text)
        body = listed.json()
        self.assertNotIn(host, {h.get("hostname") for h in body["active_hosts"]})
        offline = next(h for h in body["inactive_hosts"] if h.get("hostname") == host)
        reason = offline["offline_reason"]
        self.assertIn("No heartbeat for", reason)
        self.assertIn("day", reason)
        self.assertIn("LOGIN_FAIL", reason)
        self.assertIn("authentication failure on tty", reason)
        self.assertIn("CPU 41%", reason)
        self.assertIn("memory 40%", reason)
        self.assertIn("disk 77%", reason)
        self.assertEqual(offline["last_event"]["event_type"], "LOGIN_FAIL")
        self.assertEqual(offline["last_status"]["disk_percent"], 77.0)
        self.assertIn(keeper, self._names(body))

        forbidden = self.client.delete(
            f"/hosts/{host}",
            params={"client_id": org_a},
            headers={"api-key": key_a},
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)
        self.assertGreater(_counts(host, org_a)["heartbeats"], 0)

        missing = self.client.delete(
            "/hosts/not-a-real-host",
            params={"client_id": org_a},
            headers=self.op,
        )
        self.assertEqual(missing.status_code, 404, missing.text)

        removed = self.client.delete(
            f"/hosts/{host}",
            params={"client_id": org_a},
            headers=self.op,
        )
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertGreater(removed.json()["deleted"]["heartbeats"], 0)
        self.assertGreater(removed.json()["deleted"]["logs"], 0)

        after = self.client.get("/hosts", params={"client_id": org_a}, headers=self.op)
        self.assertNotIn(host, self._names(after.json()))
        self.assertIn(keeper, self._names(after.json()))
        gone = _counts(host, org_a)
        self.assertEqual(gone["heartbeats"], 0)
        self.assertEqual(gone["logs"], 0)
        self.assertEqual(gone["system_status"], 0)
        self.assertEqual(gone["host_metrics"], 0)
        self.assertEqual(gone["alert_history"], 1)

        still_there = self.client.get("/hosts", params={"client_id": org_b}, headers=self.op)
        self.assertIn(host, self._names(still_there.json()))
        self.assertGreater(_counts(host, org_b)["heartbeats"], 0)

    def test_log_only_host_is_removed_too(self):
        suffix = uuid.uuid4().hex[:8]
        host = f"logonly-{suffix}"
        created = self.client.post(
            "/clients",
            json={"name": f"Log Org {suffix}", "site_name": "hq"},
            headers=self.op,
        )
        self.assertEqual(created.status_code, 200, created.text)
        org = created.json()["client_id"]
        key = created.json()["agent_api_key"]
        ingested = self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}", host, "old log line")]},
            headers={"api-key": key},
        )
        self.assertEqual(ingested.status_code, 200, ingested.text)
        conn = psycopg2.connect(
            host="127.0.0.1", port=55432, dbname="heimdall", user="heimdall", password="heimdall"
        )
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM heartbeats WHERE source_host = %s AND client_id = %s",
            (host, org),
        )
        conn.commit()
        conn.close()

        listed = self.client.get("/hosts", params={"client_id": org}, headers=self.op)
        offline = [h for h in listed.json()["inactive_hosts"] if h.get("hostname") == host]
        self.assertEqual(len(offline), 1, listed.text)
        self.assertIn("No agent heartbeat", offline[0]["offline_reason"])
        self.assertIn("old log line", offline[0]["offline_reason"])

        removed = self.client.delete(f"/hosts/{host}", params={"client_id": org}, headers=self.op)
        self.assertEqual(removed.status_code, 200, removed.text)
        after = self.client.get("/hosts", params={"client_id": org}, headers=self.op)
        self.assertNotIn(host, self._names(after.json()))
        self.assertEqual(_counts(host, org)["logs"], 0)

    def test_dashboard_offline_controls_are_labeled(self):
        html_path = os.path.join(os.path.dirname(__file__), "..", "ui", "index.html")
        with open(html_path, encoding="utf-8") as handle:
            html = handle.read()
        for label in (
            "Remove selected",
            "Remove all inactive",
            "Why offline",
            "Select all offline systems",
            "WHY OFFLINE",
            "Remove this system",
        ):
            self.assertIn(label, html)
        self.assertNotIn("'api_key': API_KEY", html)


if __name__ == "__main__":
    unittest.main()
