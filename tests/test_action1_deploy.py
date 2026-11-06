#!/usr/bin/env python3
"""Script builder and Action1 JSON retries. No live tenant and no database."""

import json
import os
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ.setdefault("SIEM_TEST_MODE", "1")
os.environ.setdefault("SIEM_DB_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_DB_PORT", "55432")
os.environ.setdefault("SIEM_DB_NAME", "heimdall")
os.environ.setdefault("SIEM_DB_USER", "heimdall")
os.environ.setdefault("SIEM_DB_PASSWORD", "heimdall")
os.environ["SIEM_ACTION1_MIN_INTERVAL"] = "0"
os.environ.pop("SIEM_PUBLIC_URL", None)

from core.action1_client import Action1Client, Action1Error
from core.action1_deploy import bash_quote, build_jobs, ps_quote, resolve_hub_url


class JsonRetryStandIn(BaseHTTPRequestHandler):
    seen = []
    instance_tries = 0

    def log_message(self, fmt, *args):
        return

    def _json(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        path = urllib.parse.urlsplit(self.path).path
        JsonRetryStandIn.seen.append({
            "path": path,
            "body": body,
            "content_type": self.headers.get("Content-Type") or "",
            "auth": self.headers.get("Authorization") or "",
        })
        if path.endswith("/oauth2/token"):
            self._json({"access_token": "test-token", "expires_in": 3600})
            return
        if path.endswith("/automations/instances/org-1"):
            JsonRetryStandIn.instance_tries += 1
            if JsonRetryStandIn.instance_tries == 1:
                self._json({"error": "unauthorized"}, 401)
                return
            self._json({"id": "auto-retried"})
            return
        self._json({"error": "not found"}, 404)


class TestDeployScripts(unittest.TestCase):
    def test_quotes_keep_a_key_inside_one_string(self):
        self.assertEqual(ps_quote("a'b"), "'a''b'")
        self.assertEqual(bash_quote("a'b"), "'a'\\''b'")

    def test_localhost_is_refused(self):
        with self.assertRaises(Action1Error) as caught:
            resolve_hub_url("http://127.0.0.1:8010")
        self.assertEqual(caught.exception.status, 400)

    def test_jobs_group_platforms_and_hide_the_script(self):
        key = "agent-key-'quoted"
        plan = build_jobs(
            [
                {"action1_org_id": "org-a", "endpoint_id": "win-1", "name": "win", "platform": "Windows"},
                {"action1_org_id": "org-a", "endpoint_id": "win-2", "name": "win-2", "platform": "Windows"},
                {"action1_org_id": "org-a", "endpoint_id": "mac-1", "name": "mac", "platform": "Mac"},
                {"action1_org_id": "org-b", "endpoint_id": "lin-1", "name": "lin", "platform": "Linux"},
                {"action1_org_id": "org-a", "endpoint_id": "other", "name": "phone", "platform": "Android"},
            ],
            "http://10.1.1.8:8010/",
            key,
            "sensor-1",
            "pihole",
        )
        self.assertEqual(plan["hub_url"], "http://10.1.1.8:8010")
        self.assertEqual(plan["role"], "pihole")
        self.assertEqual(plan["skipped"][0]["name"], "phone")
        public = json.dumps([job["public"] for job in plan["jobs"]])
        self.assertNotIn(key, public)
        self.assertNotIn("run_script_text", public)
        bodies = {job["public"]["platform"] + ":" + job["org"]: job["body"] for job in plan["jobs"]}
        self.assertEqual(list(bodies), ["windows:org-a", "macos:org-a", "linux:org-b"])
        windows = bodies["windows:org-a"]["actions"][0]["params"]["run_script_text"]
        mac = bodies["macos:org-a"]["actions"][0]["params"]["run_script_text"]
        linux = bodies["linux:org-b"]["actions"][0]["params"]["run_script_text"]
        self.assertIn("/install/files/agent_windows.ps1", windows)
        self.assertIn("powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dest", windows)
        self.assertNotIn('cmd.exe /c `"', windows)
        self.assertIn("$ProgressPreference = 'SilentlyContinue'", windows)
        self.assertNotIn("HeimdallAgent.exe", windows)
        self.assertNotIn("/install/windows", windows)
        self.assertNotIn("schtasks.exe /End", windows)
        self.assertIn("schtasks /End /TN HeimdallAgent >nul 2>&1", windows)
        self.assertIn("$ErrorActionPreference = 'Continue'", windows)
        self.assertIn("agent-key-''quoted", windows)
        self.assertNotIn("--role", windows)
        self.assertIn("/install/macos", mac)
        self.assertIn("agent-key-'\\''quoted", mac)
        self.assertNotIn("--role", mac)
        self.assertIn("/install/linux", linux)
        self.assertIn("--role", linux)
        self.assertIn("pihole", linux)
        self.assertEqual(
            [item["id"] for item in bodies["windows:org-a"]["endpoints"]],
            ["win-1", "win-2"],
        )

    def test_json_body_is_sent_again_after_a_401(self):
        JsonRetryStandIn.seen = []
        JsonRetryStandIn.instance_tries = 0
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), JsonRetryStandIn)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            client = Action1Client(
                f"http://127.0.0.1:{port}/api/3.0",
                "client",
                "secret",
                min_interval=0,
            )
            created = client.create_automation_instance("org-1", {"name": "Install", "secret_script": "hide-me"})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(created["id"], "auto-retried")
        instance_calls = [row for row in JsonRetryStandIn.seen if row["path"].endswith("/automations/instances/org-1")]
        self.assertEqual(len(instance_calls), 2)
        self.assertEqual(instance_calls[0]["body"], instance_calls[1]["body"])
        self.assertIn("hide-me", instance_calls[0]["body"])
        self.assertTrue(instance_calls[0]["content_type"].startswith("application/json"))
        self.assertEqual(instance_calls[1]["auth"], "Bearer test-token")


if __name__ == "__main__":
    unittest.main()
