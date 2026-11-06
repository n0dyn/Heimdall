#!/usr/bin/env python3
"""Action1 sync against a local stand-in. No live tenant and no Telegram send."""

import json
import os
import threading
import unittest
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"
os.environ["SIEM_DB_HOST"] = "127.0.0.1"
os.environ["SIEM_DB_PORT"] = "55432"
os.environ["SIEM_DB_NAME"] = "heimdall"
os.environ["SIEM_DB_USER"] = "heimdall"
os.environ["SIEM_DB_PASSWORD"] = "heimdall"
os.environ["SIEM_ACTION1_MIN_INTERVAL"] = "0"

import psycopg2
from fastapi.testclient import TestClient

from core import server_api
from core.database_pg import get_host_status, init_database, record_heartbeat


SECRET = "standin-secret-9f3a"
STATE = {
    "org_id": "org-1",
    "org_name": "Contoso",
    "endpoints": [],
    "token_bodies": [],
    "content_types": [],
    "paths": [],
    "deleted": [],
    "instances": [],
    "vuln_tries": 0,
}


class Action1StandIn(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _json(self, payload, status=200, headers=None):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode() if length else ""

    def _authorized(self):
        if self.headers.get("Authorization") != "Bearer test-token":
            self._json({"error": "unauthorized"}, 401)
            return False
        return True

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        STATE["paths"].append(("POST", parsed.path))
        body = self._read_body()
        if parsed.path == "/api/3.0/oauth2/token":
            STATE["token_bodies"].append(body)
            STATE["content_types"].append(self.headers.get("Content-Type") or "")
            if STATE.get("reject_token"):
                self._json({"error": "unauthorized"}, 401)
                return
            self._json({"access_token": "test-token", "expires_in": 3600, "token_type": "bearer"})
            return
        if parsed.path.startswith("/api/3.0/automations/instances/"):
            if not self._authorized():
                return
            if STATE.get("deny_automations"):
                self._json({"error": "forbidden"}, 403)
                return
            try:
                parsed_body = json.loads(body or "{}")
            except json.JSONDecodeError:
                parsed_body = {"raw": body}
            STATE["instances"].append({
                "path": parsed.path,
                "body": parsed_body,
                "content_type": self.headers.get("Content-Type") or "",
            })
            self._json({
                "id": f"auto-{len(STATE['instances'])}",
                "type": "PolicyInstance",
                "actions": parsed_body.get("actions") if isinstance(parsed_body, dict) else [],
            })
            return
        self._json({"error": "not found"}, 404)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        STATE["paths"].append(("GET", parsed.path))
        if not self._authorized():
            return
        path = parsed.path
        org = STATE["org_id"]
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/api/3.0/organizations":
            self._json({"items": [{"id": org, "name": STATE["org_name"], "type": "Organization"}]})
            return
        if path == f"/api/3.0/endpoints/managed/{org}":
            rows = STATE["endpoints"]
            if "from" in query:
                self._json({"items": rows[1:]})
            else:
                page = {"items": rows[:1]}
                if len(rows) > 1:
                    page["next_page"] = f"/api/3.0/endpoints/managed/{org}?from=50"
                self._json(page)
            return
        if path == f"/api/3.0/updates/{org}":
            self._json({"items": [{"id": "upd-1", "name": "KB5001", "severity": "Critical"}]})
            return
        if path == f"/api/3.0/vulnerabilities/{org}":
            if STATE["vuln_tries"] == 0:
                STATE["vuln_tries"] += 1
                self._json({}, 429, {"Retry-After": "0"})
                return
            if STATE.get("vuln_offset"):
                start = int((query.get("from") or ["0"])[0] or 0)
                limit = int((query.get("limit") or ["50"])[0] or 50)
                cap = STATE.get("vuln_page_cap")
                if cap:
                    limit = min(limit, int(cap))
                rows = STATE["vulns"]
                self._json({
                    "items": rows[start:start + limit],
                    "from": start,
                    "limit": limit,
                    "total_items": len(rows),
                })
                return
            self._json({"items": STATE["vulns"]})
            return
        if path == f"/api/3.0/endpoints/groups/{org}":
            self._json({"items": [{"id": "g1", "name": "Servers", "type": "EndpointGroup"}]})
            return
        if path == "/api/3.0/packages/all":
            if STATE.get("packages_total"):
                self._json({
                    "items": [{"id": "pkg1", "name": "7-Zip"}],
                    "total_items": STATE["packages_total"],
                    "next_page": "/api/3.0/packages/all?from=50",
                })
                return
            self._json({"items": [{"id": "pkg1", "name": "7-Zip"}]})
            return
        if path == "/api/3.0/reports/all":
            self._json({"items": [{"id": "r1", "name": "Missing Updates"}]})
            return
        if path == "/api/3.0/users":
            self._json({"items": [{
                "id": "u1",
                "name": "Ops",
                "email": "ops@example.com",
                "password": "should-not-store",
                "client_secret": "nope",
            }]})
            return
        self._json({"error": "not found", "path": path}, 404)

    def do_DELETE(self):
        parsed = urllib.parse.urlsplit(self.path)
        STATE["paths"].append(("DELETE", parsed.path))
        if not self._authorized():
            return
        STATE["deleted"].append(parsed.path)
        self._json({})


def setUpModule():
    init_database()


def _query(sql, params):
    conn = psycopg2.connect(
        host="127.0.0.1", port=55432, dbname="heimdall", user="heimdall", password="heimdall",
    )
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall() if cur.description else []
    conn.commit()
    conn.close()
    return rows


class TestAction1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Action1StandIn)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        os.environ["SIEM_ACTION1_BASE_URL"] = f"http://127.0.0.1:{cls.port}/api/3.0"
        cls.client = TestClient(server_api.app)
        cls.op = {"api-key": "test-operator-key"}

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        _query("DELETE FROM action1_endpoints", ())
        _query("DELETE FROM action1_links", ())
        _query("DELETE FROM action1_snapshots", ())
        _query("DELETE FROM config WHERE key = 'ACTION1_CURSORS'", ())
        suffix = uuid.uuid4().hex[:8]
        self.suffix = suffix
        STATE["org_id"] = f"org-{suffix}"
        STATE["org_name"] = f"Contoso {suffix}"
        STATE["endpoints"] = [
            {
                "id": f"ep-{suffix}-1",
                "name": f"a1-{suffix}-1",
                "status": "Connected",
                "OS": "Windows 11",
                "platform": "Windows",
                "address": "198.51.100.21",
                "user": "alice",
                "last_seen": "2026-10-15T12:00:00Z",
                "missing_critical_updates": 2,
                "missing_other_updates": 1,
                "agent_version": "5.0",
            },
            {
                "id": f"ep-{suffix}-2",
                "name": f"a1-{suffix}-2",
                "status": "Disconnected",
                "OS": "Windows 10",
                "platform": "Windows",
                "address": "198.51.100.22",
                "user": "bob",
                "last_seen": "2026-10-01T12:00:00Z",
                "missing_critical_updates": 0,
                "missing_other_updates": 0,
            },
        ]
        STATE["vulns"] = [{
            "id": f"CVE-2024-{suffix}",
            "cve_id": f"CVE-2024-{suffix}",
            "name": "Example vuln",
            "severity": "Critical",
            "cvss_score": 9.8,
        }]
        STATE["reject_token"] = False
        STATE["token_bodies"] = []
        STATE["content_types"] = []
        STATE["paths"] = []
        STATE["deleted"] = []
        STATE["instances"] = []
        STATE["deny_automations"] = False
        STATE["vuln_tries"] = 0
        STATE["vuln_offset"] = False
        STATE["vuln_page_cap"] = None
        STATE["packages_total"] = None

    def _save(self, secret=SECRET, page_critical=False, region="NorthAmerica", client_id="action1-client"):
        return self.client.post("/action1/config", headers=self.op, json={
            "region": region,
            "client_id": client_id,
            "client_secret": secret,
            "page_critical": page_critical,
        })

    def _org(self):
        created = self.client.post(
            "/clients",
            json={"name": f"Action1 Org {self.suffix}", "site_name": "hq"},
            headers=self.op,
        )
        self.assertEqual(created.status_code, 200, created.text)
        return created.json()["client_id"], created.json()["agent_api_key"]

    def _link(self, client_id):
        linked = self.client.post("/action1/links", headers=self.op, json={
            "action1_org_id": STATE["org_id"],
            "action1_org_name": STATE["org_name"],
            "client_id": client_id,
        })
        self.assertEqual(linked.status_code, 200, linked.text)
        return linked.json()["link"]

    def _events(self, client_id):
        listed = self.client.get(
            "/events",
            headers=self.op,
            params={"os_type": "ACTION1", "client_id": client_id, "limit": 200},
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        return listed.json()["events"]

    def test_secret_stays_on_the_server(self):
        saved = self._save()
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertNotIn(SECRET, saved.text)
        self.assertNotIn("client_secret", saved.json()["settings"])

        blank = self._save(secret="")
        self.assertEqual(blank.status_code, 200, blank.text)
        checked = self.client.post("/action1/test", headers=self.op)
        self.assertEqual(checked.status_code, 200, checked.text)
        self.assertNotIn(SECRET, checked.text)
        parsed = urllib.parse.parse_qs(STATE["token_bodies"][-1])
        self.assertEqual(parsed["client_secret"][0], SECRET)
        self.assertTrue(STATE["content_types"][-1].startswith("application/x-www-form-urlencoded"))
        self.assertNotIn("{", STATE["token_bodies"][-1])

        refused = self._save(region="AsiaPacific")
        self.assertEqual(refused.status_code, 400, refused.text)

        state = self.client.get("/action1", headers=self.op)
        self.assertEqual(state.status_code, 200, state.text)
        self.assertNotIn(SECRET, state.text)
        self.assertNotIn("should-not-store", state.text)
        self.assertTrue(state.json()["settings"]["secret_configured"])
        self.assertIn(STATE["org_name"], state.text)

        missing = self.client.get("/action1")
        self.assertEqual(missing.status_code, 401)

    def test_token_refusal_names_the_saved_region(self):
        saved = self._save(region="NorthAmerica")
        self.assertEqual(saved.status_code, 200, saved.text)
        STATE["reject_token"] = True
        refused = self.client.post("/action1/test", headers=self.op)
        self.assertEqual(refused.status_code, 502, refused.text)
        detail = refused.json()["detail"]
        self.assertIn("North America", detail)
        self.assertIn("region where it was created", detail)
        self.assertNotIn("North America 2", detail)
        self.assertNotIn(SECRET, refused.text)

    def test_sync_reads_inventory_without_host_down(self):
        client_id, _agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        link = self._link(client_id)
        self.assertEqual(link["site_id"], f"{client_id}-action1")

        synced = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(synced.status_code, 200, synced.text)
        summary = synced.json()["summary"]
        self.assertGreaterEqual(summary["endpoints"], 2)
        self.assertGreater(summary["events_inserted"], 0)
        self.assertEqual(summary["errors"], [])
        joined = " ".join(path for _method, path in STATE["paths"])
        self.assertNotIn("/policies/", joined)
        self.assertNotIn("/remediations", joined)
        self.assertGreaterEqual(STATE["vuln_tries"], 1)

        state = self.client.get("/action1", headers=self.op).json()
        names = {row["name"] for row in state["endpoints"]}
        self.assertIn(f"a1-{self.suffix}-1", names)
        self.assertIn(f"a1-{self.suffix}-2", names)
        self.assertEqual(
            next(row["status"] for row in state["endpoints"] if row["name"].endswith("-1")),
            "Connected",
        )
        self.assertIn("Servers", [row["name"] for row in state["groups"]])
        self.assertIn("7-Zip", [row["name"] for row in state["packages"]])
        self.assertIn("Missing Updates", [row["name"] for row in state["reports"]])
        self.assertEqual(state["users"][0]["email"], "ops@example.com")
        self.assertNotIn("password", state["users"][0])
        self.assertNotIn(SECRET, json.dumps(state))

        events = self._events(client_id)
        self.assertTrue(all(event["severity"] <= 3 for event in events))
        critical = [
            event for event in events
            if event["source_host"] == f"a1-{self.suffix}-1" and "missing critical updates" in event["raw_message"]
        ]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["severity"], 3)
        self.assertEqual(critical[0]["event_type"], "MISSING_UPDATE")
        self.assertEqual(critical[0]["source_ip"], "198.51.100.21")
        other = [
            event for event in events
            if event["source_host"] == f"a1-{self.suffix}-1" and "missing other updates" in event["raw_message"]
        ]
        self.assertEqual(other[0]["severity"], 2)
        vulns = [event for event in events if event["event_type"] == "VULNERABILITY"]
        self.assertEqual(vulns[0]["severity"], 3)
        self.assertEqual(vulns[0]["signature"], f"CVE-2024-{self.suffix}")

        hosts = self.client.get("/hosts", headers=self.op, params={"client_id": client_id})
        listed = {
            host.get("hostname") or host.get("source_host")
            for host in (hosts.json().get("active_hosts") or []) + (hosts.json().get("inactive_hosts") or [])
        }
        self.assertNotIn(f"a1-{self.suffix}-1", listed)
        self.assertNotIn(f"a1-{self.suffix}-2", listed)
        self.assertNotIn(STATE["org_name"], listed)
        waiting = hosts.json().get("needs_agent_hosts") or []
        waiting_names = {host.get("hostname") for host in waiting}
        self.assertEqual(waiting_names, {f"a1-{self.suffix}-1", f"a1-{self.suffix}-2"})
        self.assertTrue(all(
            host.get("agent_label") == "Heimdall agent needs install"
            and host.get("heimdall_agent") == "needs_install"
            for host in waiting
        ))
        state_rows = {row["name"]: row for row in state["endpoints"]}
        self.assertEqual(
            state_rows[f"a1-{self.suffix}-1"]["heimdall_agent_label"],
            "Heimdall agent needs install",
        )
        beats = _query(
            "SELECT COUNT(*) FROM heartbeats WHERE client_id = %s AND source_host LIKE %s",
            (client_id, f"a1-{self.suffix}%"),
        )
        self.assertEqual(beats[0][0], 0)
        for event in events:
            sent = _query(
                "SELECT COUNT(*) FROM alert_history WHERE event_id = %s",
                (event["event_id"],),
            )
            self.assertEqual(sent[0][0], 0)

        _query(
            """
            INSERT INTO action1_endpoints (action1_org_id, endpoint_id, client_id, name)
            VALUES (%s, %s, %s, 'stale-endpoint')
            """,
            (STATE["org_id"], f"stale-{self.suffix}", client_id),
        )
        again = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(again.status_code, 200, again.text)
        self.assertEqual(again.json()["summary"]["events_inserted"], 0)
        self.assertGreater(again.json()["summary"]["events_skipped"], 0)
        self.assertEqual(len(self._events(client_id)), len(events))
        left = self.client.get("/action1", headers=self.op).json()["endpoints"]
        self.assertFalse(any(row["endpoint_id"] == f"stale-{self.suffix}" for row in left))
        self.assertEqual(len(left), 2)

        with open(get_host_status.__code__.co_filename, encoding="utf-8") as handle:
            src = handle.read()
        start = src.index("def get_host_status")
        chunk = src[start:src.index("\ndef check_alert_sent", start)]
        self.assertIn("h.os_type <> 'UNIFI'", chunk)
        self.assertIn("l.os_type <> 'UNIFI'", chunk)
        self.assertIn("h.os_type <> 'ACTION1'", chunk)
        self.assertIn("l.os_type <> 'ACTION1'", chunk)

    def test_opt_in_and_confirmed_delete(self):
        client_id, _agent = self._org()
        self.assertEqual(self._save(page_critical=True).status_code, 200)
        self._link(client_id)
        synced = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(synced.status_code, 200, synced.text)
        events = self._events(client_id)
        critical = next(
            event for event in events
            if event["source_host"] == f"a1-{self.suffix}-1" and "missing critical updates" in event["raw_message"]
        )
        self.assertEqual(critical["severity"], 4)
        vuln = next(event for event in events if event["event_type"] == "VULNERABILITY")
        self.assertEqual(vuln["severity"], 4)
        sent = _query(
            "SELECT COUNT(*) FROM alert_history WHERE event_id = %s",
            (critical["event_id"],),
        )
        self.assertEqual(sent[0][0], 0)

        endpoint_id = f"ep-{self.suffix}-1"
        removed = self.client.delete(
            f"/action1/endpoints/{STATE['org_id']}/{endpoint_id}",
            headers=self.op,
        )
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertTrue(any(endpoint_id in path for path in STATE["deleted"]))
        left = self.client.get("/action1", headers=self.op).json()["endpoints"]
        self.assertFalse(any(row["endpoint_id"] == endpoint_id for row in left))
        self.assertTrue(any(event["event_id"] == critical["event_id"] for event in self._events(client_id)))

    def test_ingest_does_not_heartbeat(self):
        host = f"ingest-a1-{self.suffix}"
        ingested = self.client.post("/ingest", headers=self.op, json={"events": [{
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-10-15T00:00:00Z",
            "source_host": host,
            "os_type": "ACTION1",
            "event_type": "VULNERABILITY",
            "severity": 2,
            "source_ip": "N/A",
            "user": "system",
            "raw_message": "synthetic action1 finding",
        }]})
        self.assertEqual(ingested.status_code, 200, ingested.text)
        beats = _query(
            "SELECT COUNT(*) FROM heartbeats WHERE source_host = %s",
            (host,),
        )
        self.assertEqual(beats[0][0], 0)
        status = get_host_status(5)
        names = {row["source_host"] for row in status["active"] + status["inactive"]}
        self.assertNotIn(host, names)

    def test_agent_cannot_call_action1(self):
        _client_id, agent = self._org()
        headers = {"api-key": agent}
        self.assertEqual(self.client.get("/action1", headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/action1/sync", headers=headers).status_code, 403)
        self.assertEqual(
            self.client.delete("/action1/endpoints/org/ep", headers=headers).status_code,
            403,
        )
        self.assertEqual(self.client.post("/action1/deploy", headers=headers, json={}).status_code, 403)

    def test_agent_checkin_marks_installed_and_leaves_the_rest(self):
        client_id, _agent = self._org()
        other, _other_agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        self._link(client_id)
        synced = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(synced.status_code, 200, synced.text)

        before = self.client.get("/hosts", headers=self.op, params={"client_id": client_id})
        self.assertEqual(before.status_code, 200, before.text)
        body = before.json()
        self.assertEqual(
            {host["hostname"] for host in body["needs_agent_hosts"]},
            {f"a1-{self.suffix}-1", f"a1-{self.suffix}-2"},
        )
        orgs = self.client.get("/clients", headers=self.op).json()["clients"]
        self.assertEqual(next(row["host_count"] for row in orgs if row["id"] == client_id), 2)

        # An agent in another organization does not satisfy this organization's computer.
        self.assertTrue(record_heartbeat(
            f"a1-{self.suffix}-1.local", "LINUX", other, f"{other}-office",
        ))
        still = self.client.get("/action1", headers=self.op, params={"client_id": client_id}).json()
        pending = next(row for row in still["endpoints"] if row["name"].endswith("-1"))
        self.assertEqual(pending["heimdall_agent"], "needs_install")

        self.assertTrue(record_heartbeat(
            f"A1-{self.suffix}-1.local", "LINUX", client_id, f"{client_id}-action1",
        ))
        after = self.client.get("/hosts", headers=self.op, params={"client_id": client_id}).json()
        self.assertEqual(
            {host["hostname"] for host in after["needs_agent_hosts"]},
            {f"a1-{self.suffix}-2"},
        )
        active = next(
            host for host in after["active_hosts"]
            if host["hostname"].lower().startswith(f"a1-{self.suffix}-1")
        )
        self.assertEqual(active["heimdall_agent"], "installed")
        self.assertEqual(active["agent_label"], "Heimdall agent installed")
        self.assertNotIn(
            f"a1-{self.suffix}-2",
            {host["hostname"] for host in after["inactive_hosts"]},
        )
        state = self.client.get("/action1", headers=self.op, params={"client_id": client_id}).json()
        by_name = {row["name"]: row for row in state["endpoints"]}
        self.assertEqual(by_name[f"a1-{self.suffix}-1"]["heimdall_agent_label"], "Heimdall agent installed")
        self.assertEqual(by_name[f"a1-{self.suffix}-2"]["heimdall_agent_label"], "Heimdall agent needs install")
        orgs = self.client.get("/clients", headers=self.op).json()["clients"]
        self.assertEqual(next(row["host_count"] for row in orgs if row["id"] == client_id), 2)

        elsewhere = self.client.get("/hosts", headers=self.op, params={
            "client_id": client_id,
            "site_id": f"{client_id}-other-site",
        }).json()
        self.assertEqual(elsewhere["needs_agent_hosts"], [])
        hidden = self.client.get("/hosts", headers=self.op, params={"client_id": other}).json()
        self.assertNotIn(
            f"a1-{self.suffix}-2",
            {host.get("hostname") for host in hidden.get("needs_agent_hosts") or []},
        )
        beats = _query(
            "SELECT COUNT(*) FROM heartbeats WHERE os_type = 'ACTION1' AND source_host LIKE %s",
            (f"%{self.suffix}%",),
        )
        self.assertEqual(beats[0][0], 0)

    def test_dashboard_labels(self):
        with open("ui/index.html", encoding="utf-8") as handle:
            html = handle.read()
        self.assertIn('data-page="action1"', html)
        self.assertIn(">Action1<", html)
        self.assertIn('id="action1-region"', html)
        self.assertIn('value="NorthAmerica"', html)
        self.assertIn('value="NorthAmerica-2"', html)
        self.assertIn('value="Europe"', html)
        self.assertIn('value="Australia"', html)
        self.assertIn('value="UnitedKingdom"', html)
        self.assertNotIn("AsiaPacific", html)
        self.assertNotIn("app.ap.action1.com", html)
        self.assertIn("app.na-2.action1.com", html)
        self.assertIn("A client id works only in the region where it was created.", html)
        self.assertIn("Leave blank to keep the saved secret", html)
        self.assertIn('type="password"', html)
        self.assertIn("Send Telegram for critical findings", html)
        self.assertIn("Sync now", html)
        self.assertIn("last.budget", html)
        self.assertIn("did not stop this sync for a request limit", html)
        self.assertIn("No Action1 organization is linked to ", html)
        self.assertIn("withClient(`${API_URL}/action1`)", html)
        self.assertIn("url.searchParams.set('client_id', selectedClientId)", html)
        self.assertIn("does not install software", html)
        self.assertIn("Install Heimdall agent", html)
        self.assertIn('id="action1-deploy-role"', html)
        self.assertIn('value="firewall"', html)
        self.assertIn('value="pihole"', html)
        self.assertIn("data-action1-pick", html)
        self.assertIn("/action1/deploy", html)
        self.assertIn("This deletes that managed endpoint in Action1", html)
        self.assertIn(">MISSING_UPDATE<", html)
        self.assertIn(">VULNERABILITY<", html)
        self.assertIn("Heimdall agent needs install", html)
        self.assertIn("NEEDS HEIMDALL AGENT", html)
        self.assertIn("needs_agent_hosts", html)
        self.assertNotIn("prompt(", html)
        self.assertNotIn("'api_key': API_KEY", html)

    def test_unlinked_org_does_not_see_another_orgs_action1(self):
        owner, _agent = self._org()
        other, _other_agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        self._link(owner)
        synced = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(synced.status_code, 200, synced.text)

        hidden = self.client.get("/action1", headers=self.op, params={"client_id": other})
        self.assertEqual(hidden.status_code, 200, hidden.text)
        body = hidden.json()
        self.assertEqual(body["links"], [])
        self.assertEqual(body["endpoints"], [])
        self.assertEqual(body["vulnerabilities"], [])
        self.assertEqual(body["updates"], [])
        self.assertEqual(body["groups"], [])
        self.assertEqual(body["packages"], [])
        self.assertEqual(body["reports"], [])
        self.assertEqual(body["users"], [])
        self.assertTrue(body["organizations"])

        shown = self.client.get("/action1", headers=self.op, params={"client_id": owner}).json()
        self.assertGreaterEqual(len(shown["endpoints"]), 2)
        self.assertEqual(shown["links"][0]["client_id"], owner)
        self.assertTrue(shown["vulnerabilities"])
        self.assertTrue(shown["packages"])
        self.assertTrue(all(row["client_id"] == owner for row in shown["endpoints"]))

    def test_offset_pages_finish_and_package_sample_is_not_a_limit_stop(self):
        from core.action1_sync import sync_action1

        client_id, _agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        self._link(client_id)
        STATE["vuln_offset"] = True
        STATE["vuln_page_cap"] = 1
        STATE["packages_total"] = 361
        STATE["vulns"] = [
            {"id": f"CVE-1-{self.suffix}", "cve_id": f"CVE-1-{self.suffix}", "severity": "High", "cvss_score": 7.5},
            {"id": f"CVE-2-{self.suffix}", "cve_id": f"CVE-2-{self.suffix}", "severity": "Medium", "cvss_score": 5.0},
            {"id": f"CVE-3-{self.suffix}", "cve_id": f"CVE-3-{self.suffix}", "severity": "Low", "cvss_score": 2.0},
        ]
        summary = sync_action1()
        self.assertFalse(summary["budget"])
        self.assertFalse(summary["truncated"])
        self.assertEqual(summary["errors"], [])
        self.assertEqual(summary["vulnerabilities"], 3)
        self.assertEqual(summary["vulnerabilities_total"], 3)
        self.assertEqual(summary["packages"], 1)
        self.assertEqual(summary["packages_total"], 361)
        vulns = [event for event in self._events(client_id) if event["event_type"] == "VULNERABILITY"]
        self.assertEqual(
            sorted(event["signature"] for event in vulns),
            [f"CVE-1-{self.suffix}", f"CVE-2-{self.suffix}", f"CVE-3-{self.suffix}"],
        )
        self.assertTrue(all(event["severity"] <= 3 for event in vulns))

    def test_request_cap_resumes_on_the_next_sync(self):
        from core.action1_client import Action1Client, base_url_for
        from core.action1_sync import sync_action1

        client_id, _agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        self._link(client_id)
        STATE["vuln_offset"] = True
        STATE["vuln_page_cap"] = 1
        STATE["vulns"] = [
            {"id": f"CVE-A-{self.suffix}", "cve_id": f"CVE-A-{self.suffix}", "severity": "High"},
            {"id": f"CVE-B-{self.suffix}", "cve_id": f"CVE-B-{self.suffix}", "severity": "High"},
            {"id": f"CVE-C-{self.suffix}", "cve_id": f"CVE-C-{self.suffix}", "severity": "High"},
            {"id": f"CVE-D-{self.suffix}", "cve_id": f"CVE-D-{self.suffix}", "severity": "High"},
        ]
        first = Action1Client(
            base_url_for("NorthAmerica"), "action1-client", SECRET, max_requests=8,
        )
        stopped = sync_action1(first)
        self.assertTrue(stopped["budget"])
        self.assertTrue(stopped["truncated"])
        self.assertLess(stopped["vulnerabilities"], 4)
        saved = _query("SELECT value FROM config WHERE key = 'ACTION1_CURSORS'", ())
        self.assertTrue(saved and saved[0][0])
        cursors = json.loads(saved[0][0])
        self.assertTrue(any(int(value) > 0 for value in cursors.values()))

        STATE["vuln_tries"] = 1
        finished = sync_action1()
        self.assertFalse(finished["budget"])
        self.assertFalse(finished["truncated"])
        vulns = [event for event in self._events(client_id) if event["event_type"] == "VULNERABILITY"]
        self.assertEqual(len(vulns), 4)
        cleared = _query("SELECT value FROM config WHERE key = 'ACTION1_CURSORS'", ())
        if cleared:
            self.assertEqual(json.loads(cleared[0][0]), {})

    def _deploy(self, endpoints, **extra):
        body = {
            "endpoints": endpoints,
            "hub_url": "http://10.1.1.8:8010",
            "hostname": "",
            "role": "linux",
        }
        body.update(extra)
        return self.client.post("/action1/deploy", headers=self.op, json=body)

    def test_deploy_installs_each_platform(self):
        os.environ.pop("SIEM_PUBLIC_URL", None)
        client_id, _agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        self._link(client_id)
        STATE["endpoints"].extend([
            {
                "id": f"ep-{self.suffix}-mac",
                "name": f"mac-{self.suffix}",
                "status": "Connected",
                "OS": "macOS",
                "platform": "Mac",
                "address": "198.51.100.23",
            },
            {
                "id": f"ep-{self.suffix}-lin",
                "name": f"lin-{self.suffix}",
                "status": "Connected",
                "OS": "Ubuntu",
                "platform": "Linux",
                "address": "198.51.100.24",
            },
            {
                "id": f"ep-{self.suffix}-cros",
                "name": f"cros-{self.suffix}",
                "status": "Connected",
                "OS": "ChromeOS",
                "platform": "ChromeOS",
                "address": "198.51.100.25",
            },
        ])
        synced = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(synced.status_code, 200, synced.text)
        selected = [
            {"action1_org_id": STATE["org_id"], "endpoint_id": row["id"]}
            for row in STATE["endpoints"]
        ]
        STATE["instances"] = []
        deployed = self._deploy(selected, hostname="lab-sensor", role="firewall")
        self.assertEqual(deployed.status_code, 200, deployed.text)
        payload = deployed.json()
        text = deployed.text
        self.assertNotIn("test-operator-key", text)
        self.assertNotIn("run_script_text", text)
        self.assertEqual(payload["role"], "firewall")
        self.assertEqual(payload["hub_url"], "http://10.1.1.8:8010")
        self.assertEqual(
            [row["platform"] for row in payload["instances"]],
            ["windows", "macos", "linux"],
        )
        self.assertEqual(payload["instances"][0]["endpoints"][0]["endpoint_id"], f"ep-{self.suffix}-1")
        self.assertEqual(len(payload["instances"][0]["endpoints"]), 2)
        self.assertEqual([row["name"] for row in payload["skipped"]], [f"cros-{self.suffix}"])
        self.assertEqual(len(STATE["instances"]), 3)
        by_platform = {}
        for record in STATE["instances"]:
            self.assertEqual(record["content_type"], "application/json")
            body = record["body"]
            self.assertEqual(body["retry_minutes"], "1440")
            self.assertEqual(body["actions"][0]["template_id"], "run_script")
            params = body["actions"][0]["params"]
            self.assertEqual(params["reboot_options"], {"auto_reboot": "no"})
            self.assertEqual(params["reboot_exit_codes"], "")
            self.assertIn("test-operator-key", params["run_script_text"])
            self.assertIn("http://10.1.1.8:8010", params["run_script_text"])
            self.assertIn("lab-sensor", params["run_script_text"])
            by_platform[params["platform"]] = params
        self.assertEqual(by_platform["Windows"]["run_script_language"], "PowerShell")
        self.assertIn("/install/files/agent_windows.ps1", by_platform["Windows"]["run_script_text"])
        self.assertNotIn("HeimdallAgent.exe", by_platform["Windows"]["run_script_text"])
        self.assertNotIn("--role", by_platform["Windows"]["run_script_text"])
        self.assertEqual(by_platform["Mac"]["run_script_language"], "Bash")
        self.assertIn("/install/macos", by_platform["Mac"]["run_script_text"])
        self.assertNotIn("--role", by_platform["Mac"]["run_script_text"])
        self.assertEqual(by_platform["Linux"]["run_script_language"], "Bash")
        self.assertIn("/install/linux", by_platform["Linux"]["run_script_text"])
        self.assertIn("--role", by_platform["Linux"]["run_script_text"])
        self.assertIn("firewall", by_platform["Linux"]["run_script_text"])
        windows_ids = [item["id"] for item in STATE["instances"][0]["body"]["endpoints"]]
        self.assertEqual(windows_ids, [f"ep-{self.suffix}-1", f"ep-{self.suffix}-2"])

    def test_deploy_refuses_a_hub_the_endpoints_cannot_reach(self):
        os.environ.pop("SIEM_PUBLIC_URL", None)
        refused = self._deploy(
            [{"action1_org_id": "org-missing", "endpoint_id": "ep-missing"}],
            hub_url="http://127.0.0.1:8010",
        )
        self.assertEqual(refused.status_code, 400, refused.text)
        self.assertIn("endpoints can reach", refused.text)
        self.assertFalse(any("/automations/instances/" in path for _method, path in STATE["paths"]))

    def test_deploy_names_the_automation_permission(self):
        os.environ.pop("SIEM_PUBLIC_URL", None)
        client_id, _agent = self._org()
        self.assertEqual(self._save().status_code, 200)
        self._link(client_id)
        synced = self.client.post("/action1/sync", headers=self.op)
        self.assertEqual(synced.status_code, 200, synced.text)
        STATE["deny_automations"] = True
        deployed = self._deploy([{
            "action1_org_id": STATE["org_id"],
            "endpoint_id": f"ep-{self.suffix}-1",
        }])
        self.assertEqual(deployed.status_code, 502, deployed.text)
        self.assertIn("permission to run automations", deployed.text)
        self.assertNotIn("test-operator-key", deployed.text)
        self.assertNotIn("run_script_text", deployed.text)

    def test_deploy_rejects_the_default_agent_key(self):
        os.environ.pop("SIEM_PUBLIC_URL", None)
        previous = os.environ.get("SIEM_API_KEY")
        os.environ["SIEM_API_KEY"] = "default-insecure-key-change-me"
        try:
            deployed = self._deploy([{
                "action1_org_id": STATE["org_id"],
                "endpoint_id": f"ep-{self.suffix}-1",
            }])
        finally:
            if previous is None:
                os.environ.pop("SIEM_API_KEY", None)
            else:
                os.environ["SIEM_API_KEY"] = previous
        self.assertEqual(deployed.status_code, 400, deployed.text)
        self.assertIn("still the default", deployed.text)
        self.assertFalse(any("/automations/instances/" in path for _method, path in STATE["paths"]))
