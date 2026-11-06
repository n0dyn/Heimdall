#!/usr/bin/env python3
"""Alert settings are operator-only. Telegram send code is not exercised."""

import os
import unittest
from unittest.mock import patch

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"

from fastapi.testclient import TestClient

from core import server_api
from core.tenancy import hash_api_key


class TestAlertAuth(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server_api.app)
        self.agent = "hk_agent_secret"
        self.row = {
            "role": "agent",
            "client_id": "default",
            "site_id": "default",
            "label": "agent",
        }

    def _lookup(self, key_hash):
        if key_hash == hash_api_key(self.agent):
            return self.row
        return None

    def test_agent_cannot_disable_alerts_or_delete_hosts(self):
        with patch.object(server_api, "lookup_api_key", self._lookup):
            disabled = self.client.post(
                "/alert-config/enable",
                params={"enabled": "false"},
                headers={"api-key": self.agent},
            )
            self.assertEqual(disabled.status_code, 403, disabled.text)
            deleted = self.client.delete(
                "/hosts/some-host",
                headers={"api-key": self.agent},
            )
            self.assertEqual(deleted.status_code, 403, deleted.text)

    def test_operator_updates_enable_flag_without_touching_telegram_copy(self):
        with patch.object(server_api, "set_config", return_value=True) as setter:
            resp = self.client.post(
                "/alert-config/enable",
                params={"enabled": "true"},
                headers={"api-key": "test-operator-key"},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            setter.assert_called_with("ENABLE_TELEGRAM_ALERTS", "true")

    def test_missing_key_is_unauthorized(self):
        resp = self.client.post("/alert-config/enable", params={"enabled": "true"})
        self.assertEqual(resp.status_code, 401)

    def test_unifi_ingest_does_not_record_heartbeat(self):
        """Syslog device names must not become hosts that page as down."""
        event = {
            "event_id": "unifi-hb-1",
            "timestamp": "2026-10-15T21:30:00Z",
            "source_host": "gateway",
            "os_type": "UNIFI",
            "event_type": "CONNECTION_BLOCKED",
            "severity": 2,
            "source_ip": "198.51.100.8",
            "user": "system",
            "raw_message": "blocked",
        }
        linux = dict(
            event,
            event_id="linux-hb-1",
            source_host="42",
            os_type="LINUX",
            event_type="LOGIN_FAIL",
        )
        with patch.object(server_api, "insert_events_batch", return_value=(1, 0)), \
             patch.object(server_api, "record_heartbeat") as beat:
            unifi = self.client.post(
                "/ingest",
                json={"events": [event]},
                headers={"api-key": "test-operator-key"},
            )
            self.assertEqual(unifi.status_code, 200, unifi.text)
            beat.assert_not_called()
            linux_resp = self.client.post(
                "/ingest",
                json={"events": [linux]},
                headers={"api-key": "test-operator-key"},
            )
            self.assertEqual(linux_resp.status_code, 200, linux_resp.text)
            beat.assert_called_once()
            self.assertEqual(beat.call_args.args[0], "42")
            self.assertEqual(beat.call_args.args[1], "LINUX")

    def test_hosts_follow_saved_inactive_window(self):
        def fake_get_config(key, default=None):
            if key == "ALERT_INACTIVE_THRESHOLD":
                return "5"
            return default

        with patch.object(server_api, "get_config", fake_get_config), \
             patch.object(
                 server_api,
                 "get_host_status",
                 return_value={"active": [], "inactive": [], "threshold_minutes": 5},
             ) as hosts:
            resp = self.client.get("/hosts", headers={"api-key": "test-operator-key"})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(hosts.call_args.kwargs["inactive_threshold_minutes"], 5)


if __name__ == "__main__":
    unittest.main()
