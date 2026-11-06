#!/usr/bin/env python3
"""Docker-update log parsing and organization scoping. No live SSH."""

import os
import subprocess
import tempfile
import unittest
import uuid

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"
os.environ["SIEM_DB_HOST"] = "127.0.0.1"
os.environ["SIEM_DB_PORT"] = "55432"
os.environ["SIEM_DB_NAME"] = "heimdall"
os.environ["SIEM_DB_USER"] = "heimdall"
os.environ["SIEM_DB_PASSWORD"] = "heimdall"
os.environ.setdefault("SIEM_DOCKER_KEY", os.path.join(tempfile.gettempdir(), "heimdall-docker-test-key"))
os.environ.setdefault(
    "SIEM_DOCKER_KNOWN_HOSTS",
    os.path.join(tempfile.gettempdir(), "heimdall-docker-test-known"),
)

import psycopg2
from fastapi.testclient import TestClient

from core import server_api
from core.database_pg import get_host_status, init_database, record_heartbeat
from core.docker_collect import poll_server
from core.docker_logs import LOG_NAMES, parse_chunk, reader_script, validate_log_dir

CVE_LOG = """\
[2026-10-16T20:43:07Z] ===== CVE check start (dry-run=0) =====
[2026-10-16T20:43:10Z] scan demo-app:latest (/demo-app)
open=178 fresh=178 baseline=0
fresh CVE-2024-21538
fresh GHSA-2x7j-588g-ccc2
[2026-10-16T20:49:08Z] fixable high/critical: 178, new since baseline: 178
[2026-10-16T20:49:08Z] recorded baseline of 178 fixable advisories; no update on the first scan
[2026-10-16T20:49:08Z] ===== CVE check done =====
"""

UPDATE_LOG = """\
[2026-10-16T21:00:00Z] ===== docker stack update start (dry-run=0) =====
[2026-10-16T21:00:01Z] START heimdall
[2026-10-16T21:01:00Z] FAIL heimdall: compose up failed
[2026-10-16T21:01:04Z] ===== done failures=1 =====
"""


def setUpModule():
    init_database()


def _query(sql, params=()):
    conn = psycopg2.connect(
        host="127.0.0.1", port=55432, dbname="heimdall", user="heimdall", password="heimdall",
    )
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall() if cur.description else []
    conn.commit()
    conn.close()
    return rows


class MemoryLogs:
    """Stand-in for the SSH reader. It only serves the four log names."""

    def __init__(self):
        self.files = {}
        self.inodes = {name: str(100 + index) for index, name in enumerate(LOG_NAMES)}

    def __call__(self, server, action, name=None, offset=0, limit=262144):
        if action == "list":
            lines = []
            for base in LOG_NAMES:
                if base not in self.files:
                    lines.append(f"FILE {base} MISSING")
                else:
                    data = self.files[base]
                    lines.append(f"FILE {base} SIZE {len(data)} INODE {self.inodes[base]}")
            return 0, ("\n".join(lines) + "\n").encode(), b""
        data = self.files.get(name)
        if data is None:
            return 0, b"MISSING\n", b""
        header = f"SIZE {len(data)} INODE {self.inodes[name]}\n".encode()
        return 0, header + data[offset:offset + limit], b""


class TestDockerLogParse(unittest.TestCase):
    def _parse(self, text, basename, catchup):
        return parse_chunk(
            text,
            server_id="docker-test",
            source_host="edge-01",
            source_ip="192.0.2.10",
            user="deploy",
            client_id="default",
            site_id="default",
            basename=basename,
            catchup=catchup,
        )

    def test_fresh_advisories_are_stored_and_the_first_scan_does_not_page(self):
        events = self._parse(CVE_LOG, "cve-check.log", catchup=False)
        findings = [event for event in events if event["event_type"] == "VULNERABILITY" and event["signature"]]
        self.assertEqual([event["signature"] for event in findings], [
            "CVE-2024-21538",
            "GHSA-2x7j-588g-ccc2",
        ])
        self.assertTrue(all(event["severity"] == 3 for event in findings))
        self.assertTrue(all(event["os_type"] == "DOCKER" for event in events))
        summary = next(event for event in events if event["raw_message"].startswith("fixable high/critical"))
        self.assertEqual(summary["severity"], 3)
        again = self._parse(CVE_LOG, "cve-check.log", catchup=True)
        self.assertEqual([event["event_id"] for event in events], [event["event_id"] for event in again])

    def test_a_later_scan_with_new_advisories_can_page_once(self):
        text = (
            "[2026-10-17T01:00:00Z] ===== CVE check start (dry-run=0) =====\n"
            "fresh CVE-2026-99999\n"
            "[2026-10-17T01:05:00Z] fixable high/critical: 4, new since baseline: 1\n"
        )
        live = self._parse(text, "cve-check.log", catchup=False)
        summary = next(event for event in live if "new since baseline" in event["raw_message"])
        self.assertEqual(summary["severity"], 4)
        history = self._parse(text, "cve-check.log", catchup=True)
        summary = next(event for event in history if "new since baseline" in event["raw_message"])
        self.assertEqual(summary["severity"], 3)

    def test_update_failure_pages_only_when_the_line_is_new(self):
        live = self._parse(UPDATE_LOG, "update.log", catchup=False)
        failed = next(event for event in live if event["raw_message"].startswith("FAIL"))
        self.assertEqual(failed["severity"], 4)
        self.assertEqual(failed["event_type"], "CRITICAL_ERROR")
        done = next(event for event in live if event["raw_message"].startswith("===== done"))
        self.assertEqual(done["severity"], 4)
        history = self._parse(UPDATE_LOG, "update.log", catchup=True)
        failed = next(event for event in history if event["raw_message"].startswith("FAIL"))
        self.assertEqual(failed["severity"], 3)

    def test_cache_and_other_paths_are_refused(self):
        with self.assertRaises(Exception):
            validate_log_dir("/home/deploy/.cache/docker-cve-check")
        with self.assertRaises(Exception):
            validate_log_dir("/home/deploy/logs/../.cache")
        self.assertEqual(
            validate_log_dir("/home/deploy/logs/docker-updates"),
            "/home/deploy/logs/docker-updates",
        )

    def test_reader_lists_the_four_logs_and_skips_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            log_dir = os.path.join(directory, "docker-updates")
            os.makedirs(log_dir)
            with open(os.path.join(log_dir, "cve-check.log"), "w", encoding="utf-8") as handle:
                handle.write(CVE_LOG)
            cache = os.path.join(directory, ".cache")
            os.makedirs(cache)
            listed = subprocess.run(
                ["sh", "-s", "--", "list", log_dir],
                input=reader_script().encode(),
                capture_output=True,
                check=False,
            )
            self.assertEqual(listed.returncode, 0, listed.stderr.decode())
            text = listed.stdout.decode()
            self.assertIn("FILE cve-check.log SIZE", text)
            self.assertIn("FILE update.log MISSING", text)
            self.assertIn("FILE cve-check.log.1 MISSING", text)
            self.assertIn("FILE update.log.1 MISSING", text)
            denied = subprocess.run(
                ["sh", "-s", "--", "read", cache, "cve-check.log", "0", "100"],
                input=reader_script().encode(),
                capture_output=True,
                check=False,
            )
            self.assertEqual(denied.returncode, 2)
            self.assertIn(b"DENIED", denied.stderr)


class TestDockerServers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(server_api.app)
        cls.op = {"api-key": "test-operator-key"}

    def setUp(self):
        self.suffix = uuid.uuid4().hex[:8]
        self.logs = MemoryLogs()
        self.logs.files["cve-check.log"] = CVE_LOG.encode()

    def _org(self, name):
        created = self.client.post(
            "/clients",
            json={"name": name, "site_name": "hq"},
            headers=self.op,
        )
        self.assertEqual(created.status_code, 200, created.text)
        body = created.json()
        return body["client_id"], body["site_id"], body["agent_api_key"]

    def _add(self, client_id, site_id, name):
        created = self.client.post("/docker-servers", headers=self.op, json={
            "client_id": client_id,
            "site_id": site_id,
            "name": name,
            "ssh_host": "192.0.2.10",
            "ssh_port": 22,
            "ssh_user": "deploy",
            "log_dir": "/home/deploy/logs/docker-updates",
        })
        self.assertEqual(created.status_code, 200, created.text)
        self.assertNotIn("BEGIN OPENSSH", created.text)
        return created.json()["server"]

    def tearDown(self):
        _query("DELETE FROM docker_log_cursors WHERE server_id LIKE 'docker-%%'")
        _query("DELETE FROM docker_servers WHERE name LIKE %s", (f"dock-{self.suffix}%",))
        _query("DELETE FROM logs WHERE source_host LIKE %s", (f"dock-{self.suffix}%",))
        _query("DELETE FROM heartbeats WHERE source_host = %s", (f"ghost-{self.suffix}",))

    def test_servers_stay_inside_their_organization(self):
        first, first_site, agent = self._org(f"Docker Org {self.suffix}")
        second, second_site, _agent = self._org(f"Other Org {self.suffix}")
        server = self._add(first, first_site, f"dock-{self.suffix}")
        own = self.client.get("/docker-servers", headers=self.op, params={"client_id": first})
        self.assertEqual(own.status_code, 200, own.text)
        self.assertEqual([row["id"] for row in own.json()["servers"]], [server["id"]])
        self.assertTrue(own.json()["public_key"])
        other = self.client.get("/docker-servers", headers=self.op, params={"client_id": second})
        self.assertEqual(other.json()["servers"], [])
        blocked = self.client.post("/docker-servers", headers={"api-key": agent}, json={
            "client_id": second,
            "site_id": second_site,
            "name": f"dock-{self.suffix}-nope",
            "ssh_host": "192.0.2.10",
            "ssh_user": "deploy",
            "log_dir": "/home/deploy/logs/docker-updates",
        })
        self.assertEqual(blocked.status_code, 403, blocked.text)
        rejected = self.client.post("/docker-servers", headers=self.op, json={
            "client_id": first,
            "site_id": first_site,
            "name": f"dock-{self.suffix}-cache",
            "ssh_host": "192.0.2.10",
            "ssh_user": "deploy",
            "log_dir": "/home/deploy/.cache",
        })
        self.assertEqual(rejected.status_code, 400, rejected.text)

    def test_first_collection_is_history_and_a_later_update_failure_can_page(self):
        client_id, site_id, _agent = self._org(f"Collect Org {self.suffix}")
        before = self.client.get(f"/orgs/{client_id}", headers=self.op)
        self.assertEqual(before.status_code, 200, before.text)
        server = self._add(client_id, site_id, f"dock-{self.suffix}-hub")
        added = self.client.get(f"/orgs/{client_id}", headers=self.op)
        self.assertEqual(added.json()["client"]["host_count"], before.json()["client"]["host_count"] + 1)
        first = poll_server(server, self.logs)
        self.assertTrue(first["success"], first)
        self.assertGreater(first["inserted"], 0)
        events = self.client.get("/events", headers=self.op, params={
            "os_type": "DOCKER",
            "client_id": client_id,
            "limit": 500,
        })
        self.assertEqual(events.status_code, 200, events.text)
        rows = events.json()["events"]
        text = "\n".join(row["raw_message"] for row in rows)
        self.assertIn("CVE-2024-21538", text)
        self.assertIn("GHSA-2x7j-588g-ccc2", text)
        self.assertEqual(text.count("CVE-2024-21538"), 1)
        self.assertTrue(all(row["severity"] <= 3 for row in rows))
        self.assertNotIn("docker-cve-baseline", text)
        again = poll_server(server, self.logs)
        self.assertEqual(again["inserted"], 0, again)
        self.logs.files["update.log"] = UPDATE_LOG.encode()
        third = poll_server(server, self.logs)
        self.assertGreater(third["inserted"], 0, third)
        events = self.client.get("/events", headers=self.op, params={
            "os_type": "DOCKER",
            "client_id": client_id,
            "source_host": server["name"],
            "limit": 500,
        })
        rows = events.json()["events"]
        failed = [
            row for row in rows
            if "heimdall: compose up failed" in (row["raw_message"] or "")
        ]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["severity"], 4)
        self.assertNotIn("===== done", failed[0]["raw_message"])
        self.assertFalse(any((row["raw_message"] or "").startswith("===== done") for row in rows))
        after = self.client.get(f"/orgs/{client_id}", headers=self.op)
        self.assertEqual(after.json()["client"]["host_count"], added.json()["client"]["host_count"])

    def test_docker_logs_do_not_become_offline_hosts(self):
        client_id, site_id, _agent = self._org(f"Quiet Org {self.suffix}")
        name = f"ghost-{self.suffix}"
        record_heartbeat(name, "DOCKER", client_id=client_id, site_id=site_id)
        _query("UPDATE heartbeats SET last_seen = %s WHERE source_host = %s", ("2020-01-01", name))
        status = get_host_status(client_id=client_id)
        names = [host["hostname"] for host in status["active"] + status["inactive"]]
        self.assertNotIn(name, names)

    def test_dashboard_has_labeled_docker_controls(self):
        html_path = os.path.join(os.path.dirname(__file__), "..", "ui", "index.html")
        with open(html_path, "r", encoding="utf-8") as handle:
            html = handle.read()
        self.assertIn('data-page="docker"', html)
        self.assertIn(">Docker<", html)
        self.assertIn("No docker servers in this organization", html)
        self.assertIn("cve-check.log.1", html)
        self.assertIn("update.log.1", html)
        self.assertIn("does not read .cache", html)
        self.assertIn('id="docker-host"', html)
        self.assertIn('for="docker-host"', html)
        self.assertNotIn("prompt(", html)
