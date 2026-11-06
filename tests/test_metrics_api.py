#!/usr/bin/env python3
"""Drive POST /system-status and GET /metrics/query through the shipped API."""

import os
import unittest
from datetime import datetime, timedelta, timezone

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"

from fastapi.testclient import TestClient

from core import server_api
from core.host_metrics import query_samples, status_to_samples
from core.tenancy import hash_api_key, generate_api_key


class MemoryStore:
    def __init__(self):
        self.samples = []
        self.snapshots = {}
        self.keys = {}
        self.clients = {
            "default": {
                "id": "default",
                "name": "Default",
                "telegram_chat_id": None,
                "sites": [{"id": "default", "name": "default"}],
                "host_count": 0,
                "key_prefix": "",
            }
        }
        self.sites = {"default": {"id": "default", "client_id": "default", "name": "default"}}

    def insert_metric_samples(self, samples, client_id=None, site_id=None):
        for s in samples:
            row = dict(s)
            if client_id:
                row["client_id"] = row.get("client_id") or client_id
            self.samples.append(row)
        return len(samples)

    def query_host_metrics(self, source_host=None, metric=None, client_id=None,
                           start=None, end=None, step_seconds=0, site_id=None):
        return query_samples(
            self.samples,
            source_host=source_host,
            metric=metric,
            client_id=client_id,
            start=start,
            end=end,
            step_seconds=step_seconds or 0,
        )

    def upsert_system_status(self, status):
        key = (status.get("client_id") or "default", status["source_host"])
        self.snapshots[key] = status
        return True

    def get_system_status(self, host, client_id=None):
        if client_id:
            return self.snapshots.get((client_id, host))
        for (cid, h), row in self.snapshots.items():
            if h == host:
                return row
        return None

    def record_heartbeat(self, *args, **kwargs):
        return True

    def lookup_api_key(self, key_hash):
        return self.keys.get(key_hash)

    def insert_events_batch(self, events):
        return (len(events), 0)

    def list_clients(self):
        return list(self.clients.values())

    def get_client(self, client_id):
        return self.clients.get(client_id)

    def create_client(self, client_id, name, telegram_chat_id=None, site_name="default"):
        site_id = f"{client_id}-{site_name}"
        self.clients[client_id] = {
            "id": client_id,
            "name": name,
            "slug": client_id,
            "telegram_chat_id": telegram_chat_id,
            "sites": [{"id": site_id, "name": site_name}],
            "host_count": 0,
            "key_prefix": "",
            "workspace_path": f"/org/{client_id}",
        }
        self.sites[site_id] = {"id": site_id, "client_id": client_id, "name": site_name}
        return True

    def update_client(self, client_id, name=None, telegram_chat_id=None):
        row = self.clients.get(client_id)
        if not row:
            return False
        if name is not None:
            row["name"] = name
        if telegram_chat_id is not None:
            row["telegram_chat_id"] = telegram_chat_id
        return True

    def delete_client(self, client_id):
        if client_id == "default" or client_id not in self.clients:
            return False
        self.clients.pop(client_id, None)
        return True

    def create_site(self, site_id, client_id, name):
        self.sites[site_id] = {"id": site_id, "client_id": client_id, "name": name}
        if client_id in self.clients:
            self.clients[client_id].setdefault("sites", []).append({"id": site_id, "name": name})
        return True

    def get_site(self, site_id):
        return self.sites.get(site_id)

    def update_site(self, site_id, name):
        row = self.sites.get(site_id)
        if not row:
            return False
        row["name"] = name
        return True

    def delete_site(self, site_id):
        row = self.sites.get(site_id)
        if not row:
            return False
        client_id = row["client_id"]
        count = sum(1 for s in self.sites.values() if s["client_id"] == client_id)
        if count <= 1:
            return False
        self.sites.pop(site_id)
        return True

    def delete_api_keys_for_client(self, client_id):
        return True

    def insert_api_key(self, *args, **kwargs):
        return True


class TestMetricsApi(unittest.TestCase):
    _PATCHED = (
        "insert_metric_samples",
        "query_host_metrics",
        "upsert_system_status",
        "get_system_status",
        "record_heartbeat",
        "lookup_api_key",
        "insert_events_batch",
        "list_clients",
        "get_client",
        "create_client",
        "update_client",
        "delete_client",
        "create_site",
        "get_site",
        "update_site",
        "delete_site",
        "delete_api_keys_for_client",
        "insert_api_key",
    )

    @classmethod
    def setUpClass(cls):
        cls.store = MemoryStore()
        cls._originals = {}
        for name in cls._PATCHED:
            cls._originals[name] = getattr(server_api, name)
            setattr(server_api, name, getattr(cls.store, name))
        cls.client = TestClient(server_api.app, raise_server_exceptions=True)
        cls.headers = {"api-key": "test-operator-key"}

    @classmethod
    def tearDownClass(cls):
        for name, original in cls._originals.items():
            setattr(server_api, name, original)
        cls._originals.clear()

    def _status(self, host, cpu, ts):
        return {
            "source_host": host,
            "os_type": "LINUX",
            "os_details": "test",
            "cpu_usage": cpu,
            "cpu_count": 2,
            "memory_total": 8,
            "memory_used": 4,
            "memory_percent": 50.0,
            "disk_info": [{"mount": "/", "total": 100, "used": 40, "free": 60, "percent": 40.0}],
            "network_info": [],
            "top_processes": [],
            "boot_time": "2026-08-25T00:00:00Z",
            "timestamp": ts,
        }

    def test_system_status_appends_queryable_series(self):
        t0 = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(minutes=1)
        for cpu, ts in ((11.0, t0), (22.0, t1)):
            resp = self.client.post(
                "/system-status",
                headers=self.headers,
                json={"status": self._status("lab-1", cpu, ts.strftime("%Y-%m-%dT%H:%M:%SZ"))},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertGreater(resp.json().get("samples_stored", 0), 0)

        snap = self.client.get("/system-status/lab-1", headers=self.headers)
        self.assertEqual(snap.status_code, 200)
        self.assertEqual(snap.json()["status"]["cpu_usage"], 22.0)

        q = self.client.get(
            "/metrics/query",
            headers=self.headers,
            params={
                "source_host": "lab-1",
                "metric": "cpu_usage",
                "start": "2026-08-25T12:00:00Z",
                "end": "2026-08-25T12:05:00Z",
            },
        )
        self.assertEqual(q.status_code, 200, q.text)
        points = q.json()["points"]
        self.assertGreaterEqual(len(points), 2)
        self.assertEqual([p["value"] for p in points], [11.0, 22.0])

    def test_direct_samples_endpoint(self):
        payload = {
            "samples": [
                {
                    "time": "2026-08-25T14:00:00Z",
                    "source_host": "lab-2",
                    "metric": "cpu_usage",
                    "value": 7.5,
                    "labels": {},
                }
            ]
        }
        resp = self.client.post("/metrics/samples", headers=self.headers, json=payload)
        self.assertEqual(resp.status_code, 200, resp.text)
        q = self.client.get(
            "/metrics/query",
            headers=self.headers,
            params={"source_host": "lab-2", "metric": "cpu_usage"},
        )
        self.assertTrue(any(p["value"] == 7.5 for p in q.json()["points"]))

    def test_agent_key_cannot_read_other_client(self):
        raw = generate_api_key()
        self.store.keys[hash_api_key(raw)] = {
            "role": "agent",
            "client_id": "acme",
            "site_id": "acme-hq",
            "label": "acme",
        }
        self.client.post(
            "/system-status",
            headers={"api-key": raw},
            json={"status": self._status("web-01", 5, "2026-08-25T16:00:00Z")},
        )
        other = generate_api_key()
        self.store.keys[hash_api_key(other)] = {
            "role": "agent",
            "client_id": "beta",
            "site_id": "beta-hq",
            "label": "beta",
        }
        q = self.client.get(
            "/metrics/query",
            headers={"api-key": other},
            params={"source_host": "web-01", "metric": "cpu_usage"},
        )
        self.assertEqual(q.status_code, 200)
        self.assertEqual(q.json()["points"], [])

    def test_bad_key_rejected(self):
        resp = self.client.get("/metrics/query", headers={"api-key": "nope"})
        self.assertEqual(resp.status_code, 403)

    def test_create_update_site_and_delete_client(self):
        created = self.client.post(
            "/clients",
            headers=self.headers,
            json={"name": "Acme Corp", "site_name": "hq", "telegram_chat_id": "-100"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        body = created.json()
        cid = body["client_id"]
        self.assertTrue(body.get("agent_api_key"))
        self.assertTrue(body.get("workspace_path", "").startswith("/org/"))
        orgs = self.client.get("/orgs", headers=self.headers)
        self.assertEqual(orgs.status_code, 200)
        self.assertIn("organizations", orgs.json())

        listed = self.client.get("/clients", headers=self.headers)
        names = [c["name"] for c in listed.json()["clients"]]
        self.assertIn("Acme Corp", names)

        patched = self.client.patch(
            f"/clients/{cid}",
            headers=self.headers,
            json={"name": "Acme Ltd", "telegram_chat_id": "-200"},
        )
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual(patched.json()["client"]["name"], "Acme Ltd")

        site = self.client.post(
            f"/clients/{cid}/sites",
            headers=self.headers,
            json={"name": "office"},
        )
        self.assertEqual(site.status_code, 200, site.text)
        site_id = site.json()["site"]["id"]
        self.assertTrue(site_id.startswith(cid))

        deleted = self.client.delete(f"/clients/{cid}", headers=self.headers)
        self.assertEqual(deleted.status_code, 200)
        gone = self.client.get(f"/clients/{cid}", headers=self.headers)
        self.assertEqual(gone.status_code, 404)

    def test_cannot_delete_default_client(self):
        resp = self.client.delete("/clients/default", headers=self.headers)
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
