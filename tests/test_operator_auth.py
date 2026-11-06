#!/usr/bin/env python3
"""Operator sign-in: two factors, no operator key on the network."""

import os
import tempfile
import unittest
from unittest.mock import patch

os.environ["SIEM_TEST_MODE"] = "1"
os.environ["SIEM_API_KEY"] = "test-operator-key"
os.environ["SIEM_DATA_DIR"] = tempfile.mkdtemp(prefix="heimdall-auth-")
os.environ["SIEM_BOOTSTRAP_TOKEN"] = "bootstrap-test-token"
os.environ.pop("SIEM_PUBLIC", None)

import pyotp
from fastapi.testclient import TestClient

from core import auth_store, server_api
from core.operator_auth import hash_login_secret
from core.tenancy import hash_api_key
from ui.dashboard_server import upstream_headers


def _code(secret: str) -> str:
    return pyotp.TOTP(secret).now()


class TestOperatorAuth(unittest.TestCase):
    def setUp(self):
        os.environ.pop("SIEM_PUBLIC", None)
        auth_store.reset_store(auth_store.MemoryStore())
        self.client = TestClient(server_api.app)
        self.agent = "hk_agent_secret"
        self.agent_row = {
            "role": "agent",
            "client_id": "default",
            "site_id": "default",
            "label": "agent",
        }

    def _lookup(self, key_hash):
        if key_hash == hash_api_key(self.agent):
            return self.agent_row
        return None

    def test_two_factor_session_authorizes_operator_routes(self):
        begun = self.client.post("/auth/setup/begin", json={"bootstrap_token": "bootstrap-test-token"})
        self.assertEqual(begun.status_code, 200, begun.text)
        created = self.client.post("/auth/setup/secret")
        secret = created.json()["login_secret"]
        totp = self.client.post("/auth/setup/totp/begin").json()
        confirmed = self.client.post("/auth/setup/totp/confirm", json={"code": _code(totp["secret"])})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        self.assertNotIn("bootstrap.token", os.listdir(os.environ["SIEM_DATA_DIR"]) + ["missing"])
        # A second enrollment is refused, and the login secret alone is not a session.
        again = self.client.post("/auth/setup/begin", json={"bootstrap_token": "bootstrap-test-token"})
        self.assertEqual(again.status_code, 409, again.text)
        alone = self.client.get("/alert-config")
        self.assertEqual(alone.status_code, 401, alone.text)

        first = self.client.post("/auth/login/secret", json={"secret": secret})
        self.assertEqual(first.status_code, 200, first.text)
        still = self.client.get("/alert-config")
        self.assertEqual(still.status_code, 401, still.text)
        wrong = "000000" if _code(totp["secret"]) != "000000" else "111111"
        bad = self.client.post("/auth/login/totp", json={"code": wrong})
        self.assertEqual(bad.status_code, 401, bad.text)
        good = self.client.post("/auth/login/totp", json={"code": _code(totp["secret"])})
        self.assertEqual(good.status_code, 200, good.text)

        with patch.object(server_api, "get_config", side_effect=lambda key, default=None: default):
            opened = self.client.get("/alert-config")
        self.assertEqual(opened.status_code, 200, opened.text)

        remote = TestClient(server_api.app, client=("203.0.113.9", 4444))
        remote.cookies.update(self.client.cookies)
        stolen = remote.get("/alert-config")
        self.assertEqual(stolen.status_code, 401, stolen.text)
        # The mismatch destroys the session, so the original browser is signed out too.
        with patch.object(server_api, "get_config", side_effect=lambda key, default=None: default):
            local_after = self.client.get("/alert-config")
        self.assertEqual(local_after.status_code, 401, local_after.text)

    def test_bad_enrollment_token_and_lockout(self):
        for _ in range(5):
            rejected = self.client.post("/auth/setup/begin", json={"bootstrap_token": "nope"})
            self.assertEqual(rejected.status_code, 401, rejected.text)
        locked = self.client.post("/auth/setup/begin", json={"bootstrap_token": "bootstrap-test-token"})
        self.assertEqual(locked.status_code, 429, locked.text)

    def test_recovery_code_is_single_use_and_limited(self):
        begun = self.client.post("/auth/setup/begin", json={"bootstrap_token": "bootstrap-test-token"})
        self.assertEqual(begun.status_code, 200, begun.text)
        self.client.post("/auth/setup/secret")
        totp = self.client.post("/auth/setup/totp/begin").json()
        confirmed = self.client.post("/auth/setup/totp/confirm", json={"code": _code(totp["secret"])})
        code = confirmed.json()["recovery_codes"][0]
        used = self.client.post("/auth/login/recovery", json={"code": code})
        self.assertEqual(used.status_code, 200, used.text)
        self.assertTrue(used.json()["limited"])
        with patch.object(server_api, "get_config", side_effect=lambda key, default=None: default):
            blocked = self.client.get("/alert-config")
        self.assertEqual(blocked.status_code, 403, blocked.text)
        again = self.client.post("/auth/login/recovery", json={"code": code})
        self.assertEqual(again.status_code, 401, again.text)

    def test_operator_key_from_the_network_is_rejected(self):
        remote = TestClient(server_api.app, client=("203.0.113.9", 4444))
        resp = remote.get("/hosts", headers={"api-key": "test-operator-key"})
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertIn("not accepted from the network", resp.text)

    def test_operator_key_can_still_check_in_from_the_agent_host(self):
        remote = TestClient(server_api.app, client=("203.0.113.9", 4444))
        blocked = remote.get("/hosts", headers={"api-key": "test-operator-key"})
        self.assertEqual(blocked.status_code, 403, blocked.text)
        with patch.object(server_api, "record_heartbeat", return_value=True):
            beat = remote.post(
                "/heartbeat",
                headers={
                    "api-key": "test-operator-key",
                    "source-host": "auth-checkin-host",
                    "os-type": "LINUX",
                },
            )
        self.assertEqual(beat.status_code, 200, beat.text)

    def test_public_mode_agent_cannot_read(self):
        os.environ["SIEM_PUBLIC"] = "1"
        try:
            with patch.object(server_api, "lookup_api_key", self._lookup):
                denied = self.client.get("/hosts", headers={"api-key": self.agent})
                self.assertEqual(denied.status_code, 403, denied.text)
                with patch.object(server_api, "insert_events_batch", return_value=(0, 0)):
                    event = {
                        "event_id": "pub-1",
                        "timestamp": "2026-10-15T21:30:00Z",
                        "source_host": "42",
                        "os_type": "LINUX",
                        "event_type": "LOGIN_FAIL",
                        "severity": 2,
                        "source_ip": "203.0.113.10",
                        "user": "root",
                        "raw_message": "failed",
                    }
                    allowed = self.client.post("/ingest", json={"events": [event]}, headers={"api-key": self.agent})
                self.assertEqual(allowed.status_code, 200, allowed.text)
        finally:
            os.environ.pop("SIEM_PUBLIC", None)

    def test_login_secret_is_rejected_after_a_passkey_exists(self):
        store = auth_store.get_store()
        store.put_secret("enrolled", "1")
        store.put_secret("login_hash", hash_login_secret("heimdall-test-secret"))
        store.add_passkey("cred", "key", 0)
        rejected = self.client.post("/auth/login/secret", json={"secret": "heimdall-test-secret"})
        self.assertEqual(rejected.status_code, 401, rejected.text)

    def test_passkey_options_require_a_real_origin(self):
        begun = self.client.post("/auth/setup/begin", json={"bootstrap_token": "bootstrap-test-token"})
        self.assertEqual(begun.status_code, 200, begun.text)
        options = self.client.post("/auth/setup/passkey/options")
        self.assertEqual(options.status_code, 400, options.text)
        self.assertIn("domain", options.text.lower())

    def test_proxy_does_not_forward_an_api_key(self):
        headers = upstream_headers(
            {"Api-Key": "super-secret", "Cookie": "heimdall_session=abc", "Host": "10.1.1.1:8501", "X-Forwarded-Proto": "https"},
            "203.0.113.4",
        )
        blob = " ".join(f"{key}:{value}" for key, value in headers.items()).lower()
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("api-key", blob)
        self.assertEqual(headers["Cookie"], "heimdall_session=abc")
        self.assertEqual(headers["X-Heimdall-Client-Ip"], "203.0.113.4")
        self.assertEqual(headers["X-Forwarded-Proto"], "http")


if __name__ == "__main__":
    unittest.main()
