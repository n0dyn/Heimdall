#!/usr/bin/env python3
"""Organization placement through the real API and move_endpoint.

Uses the app routes. Does not mock move_endpoint or skip ahead of it.
"""

import os
import uuid

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"
os.environ["SIEM_DB_HOST"] = "127.0.0.1"
os.environ["SIEM_DB_PORT"] = "55432"
os.environ["SIEM_DB_NAME"] = "heimdall"
os.environ["SIEM_DB_USER"] = "heimdall"
os.environ["SIEM_DB_PASSWORD"] = "heimdall"

import unittest

from fastapi.testclient import TestClient

from core import server_api
from core.database_pg import init_database


def setUpModule():
    init_database()


class TestOrgMove(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(server_api.app)
        cls.op = {"api-key": "test-operator-key"}

    def _event(self, event_id, host):
        return {
            "event_id": event_id,
            "timestamp": "2026-10-15T22:00:00+00:00",
            "source_host": host,
            "os_type": "LINUX",
            "event_type": "LOGIN_FAIL",
            "severity": 2,
            "source_ip": "203.0.113.40",
            "user": "root",
            "raw_message": "placement check",
        }

    def _names(self, payload):
        hosts = (payload.get("active_hosts") or []) + (payload.get("inactive_hosts") or [])
        return {h.get("hostname") or h.get("source_host") for h in hosts}

    def test_move_keeps_records_and_later_ingest_on_destination(self):
        suffix = uuid.uuid4().hex[:8]
        host = f"edge-{suffix}"
        other = f"other-{suffix}"
        dup = f"dup-{suffix}"

        created_a = self.client.post(
            "/clients",
            json={"name": f"Acme {suffix}", "site_name": "hq", "telegram_chat_id": "111"},
            headers=self.op,
        )
        self.assertEqual(created_a.status_code, 200, created_a.text)
        org_a = created_a.json()["client_id"]
        key_a = created_a.json()["agent_api_key"]

        created_b = self.client.post(
            "/clients",
            json={"name": f"Bravo {suffix}", "site_name": "hq"},
            headers=self.op,
        )
        self.assertEqual(created_b.status_code, 200, created_b.text)
        org_b = created_b.json()["client_id"]
        key_b = created_b.json()["agent_api_key"]

        branch = self.client.post(
            f"/clients/{org_b}/sites",
            json={"name": "branch"},
            headers=self.op,
        )
        self.assertEqual(branch.status_code, 200, branch.text)
        branch_id = branch.json()["site"]["id"]

        first_id = f"evt-{suffix}-1"
        second_id = f"evt-{suffix}-2"
        ingested = self.client.post(
            "/ingest",
            json={"events": [self._event(first_id, host)]},
            headers={"api-key": key_a},
        )
        self.assertEqual(ingested.status_code, 200, ingested.text)
        self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-b", other)]},
            headers={"api-key": key_b},
        )
        self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-da", dup)]},
            headers={"api-key": key_a},
        )
        self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-db", dup)]},
            headers={"api-key": key_b},
        )

        seen_by_a = self.client.get("/hosts", params={"client_id": org_b}, headers={"api-key": key_a})
        self.assertEqual(seen_by_a.status_code, 200, seen_by_a.text)
        self.assertIn(host, self._names(seen_by_a.json()))
        self.assertNotIn(other, self._names(seen_by_a.json()))

        forbidden_create = self.client.post(
            "/clients",
            json={"name": "Nope"},
            headers={"api-key": key_a},
        )
        self.assertEqual(forbidden_create.status_code, 403, forbidden_create.text)
        forbidden_delete = self.client.delete(f"/clients/{org_b}", headers={"api-key": key_a})
        self.assertEqual(forbidden_delete.status_code, 403, forbidden_delete.text)
        forbidden_move = self.client.post(
            "/endpoints/move",
            json={
                "source_host": host,
                "client_id": org_a,
                "destination_client_id": org_b,
                "destination_site_id": branch_id,
            },
            headers={"api-key": key_a},
        )
        self.assertEqual(forbidden_move.status_code, 403, forbidden_move.text)

        conflict = self.client.post(
            "/endpoints/move",
            json={
                "source_host": dup,
                "client_id": org_a,
                "destination_client_id": org_b,
                "destination_site_id": branch_id,
            },
            headers=self.op,
        )
        self.assertEqual(conflict.status_code, 409, conflict.text)

        moved = self.client.post(
            "/endpoints/move",
            json={
                "source_host": host,
                "client_id": org_a,
                "destination_client_id": org_b,
                "destination_site_id": branch_id,
            },
            headers=self.op,
        )
        self.assertEqual(moved.status_code, 200, moved.text)
        self.assertEqual(moved.json()["endpoint"]["client_id"], org_b)
        self.assertEqual(moved.json()["endpoint"]["site_id"], branch_id)

        beat = self.client.post(
            "/heartbeat",
            headers={"api-key": key_a, "source-host": host, "os-type": "LINUX"},
        )
        self.assertEqual(beat.status_code, 200, beat.text)
        later = self.client.post(
            "/ingest",
            json={"events": [self._event(second_id, host)]},
            headers={"api-key": key_a},
        )
        self.assertEqual(later.status_code, 200, later.text)

        source_events = self.client.get(
            "/events",
            params={"client_id": org_a, "source_host": host},
            headers=self.op,
        )
        self.assertEqual(source_events.status_code, 200, source_events.text)
        self.assertEqual(source_events.json()["total_count"], 0)
        self.assertEqual(source_events.json()["events"], [])

        dest_events = self.client.get(
            "/events",
            params={"client_id": org_b, "source_host": host},
            headers=self.op,
        )
        self.assertEqual(dest_events.status_code, 200, dest_events.text)
        body = dest_events.json()
        self.assertEqual(body["total_count"], 2)
        ids = {row["event_id"] for row in body["events"]}
        self.assertEqual(ids, {first_id, second_id})
        for row in body["events"]:
            self.assertEqual(row["client_id"], org_b)
            self.assertEqual(row["site_id"], branch_id)
            self.assertEqual(row["source_host"], host)

        source_hosts = self.client.get("/hosts", params={"client_id": org_a}, headers=self.op)
        dest_hosts = self.client.get("/hosts", params={"client_id": org_b}, headers=self.op)
        self.assertNotIn(host, self._names(source_hosts.json()))
        self.assertIn(host, self._names(dest_hosts.json()))
        placed = next(h for h in (dest_hosts.json()["active_hosts"] + dest_hosts.json()["inactive_hosts"]) if (h.get("hostname") or h.get("source_host")) == host)
        self.assertEqual(placed["client_id"], org_b)
        self.assertEqual(placed["site_id"], branch_id)

        renamed = self.client.patch(
            f"/clients/{org_a}",
            json={"name": f"Acme Renamed {suffix}", "telegram_chat_id": "222"},
            headers=self.op,
        )
        self.assertEqual(renamed.status_code, 200, renamed.text)
        self.assertEqual(renamed.json()["client"]["name"], f"Acme Renamed {suffix}")
        self.assertEqual(renamed.json()["client"]["telegram_chat_id"], "222")

        extra = self.client.post(
            f"/clients/{org_b}/sites",
            json={"name": f"temp {suffix}"},
            headers=self.op,
        )
        self.assertEqual(extra.status_code, 200, extra.text)
        extra_id = extra.json()["site"]["id"]
        renamed_site = self.client.patch(
            f"/sites/{extra_id}",
            json={"name": f"temp renamed {suffix}"},
            headers=self.op,
        )
        self.assertEqual(renamed_site.status_code, 200, renamed_site.text)
        self.assertEqual(renamed_site.json()["site"]["name"], f"temp renamed {suffix}")
        removed = self.client.delete(f"/sites/{extra_id}", headers=self.op)
        self.assertEqual(removed.status_code, 200, removed.text)

        default_delete = self.client.delete("/clients/default", headers=self.op)
        self.assertEqual(default_delete.status_code, 400, default_delete.text)

        deleted = self.client.delete(f"/clients/{org_a}", headers=self.op)
        self.assertEqual(deleted.status_code, 200, deleted.text)
        after = self.client.post(
            "/ingest",
            json={"events": [self._event(f"evt-{suffix}-gone", host)]},
            headers={"api-key": key_a},
        )
        self.assertEqual(after.status_code, 403, after.text)

    def test_dashboard_org_controls_are_labeled(self):
        html_path = os.path.join(os.path.dirname(__file__), "..", "ui", "index.html")
        with open(html_path, encoding="utf-8") as handle:
            html = handle.read()
        self.assertNotIn("prompt(", html)
        for label in (
            'for="new-client-name"',
            'for="new-client-site"',
            'for="new-client-telegram"',
            'for="edit-org-name"',
            'for="edit-org-telegram"',
            'for="edit-new-site"',
            'for="move-endpoint"',
            'for="move-dest-org"',
            'for="move-dest-site"',
            ">Organization name<",
            ">First site<",
            ">Telegram chat id<",
            ">Site name<",
            ">Endpoint<",
            ">Destination organization<",
            ">Destination site<",
            ">Move endpoint<",
        ):
            self.assertIn(label, html)
        self.assertIn("<th>Organization</th>", html)
        self.assertIn("<th>Site</th>", html)


if __name__ == "__main__":
    unittest.main()
