"""Installer contract: one config, one download URL per operating system."""

import os
import subprocess
import unittest
from pathlib import Path

from core.agent_install import FILES, PLACEHOLDER, agent_file, render_script
from agents.runtime import load_settings


ROOT = Path(__file__).resolve().parent.parent


class RenderTests(unittest.TestCase):
    def test_linux_script_keeps_the_baked_in_hub_url(self):
        text = render_script("linux", "http://hub.example:8010")
        self.assertIn('HUB_URL="http://hub.example:8010"', text)
        self.assertNotIn(PLACEHOLDER, text)
        self.assertIn("--role linux|firewall|pihole", text)
        self.assertIn("--site SITE", text)
        self.assertIn("SIEM_SITE_ID", text)

    def test_macos_and_windows_scripts_get_the_same_url(self):
        macos = render_script("macos", "http://hub.example:8010")
        windows = render_script("windows", "http://hub.example:8010")
        self.assertIn('HUB_URL="http://hub.example:8010"', macos)
        self.assertIn('[string]$ApiUrl = "http://hub.example:8010"', windows)
        self.assertIn("agent_windows.ps1", windows)
        self.assertNotIn(PLACEHOLDER, macos)
        self.assertNotIn(PLACEHOLDER, windows)

    def test_rendered_shell_scripts_parse(self):
        for platform in ("linux", "macos"):
            text = render_script(platform, "http://hub.example:8010")
            result = subprocess.run(
                ["bash", "-n"],
                input=text,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_placeholder_does_not_wipe_a_real_hub_url(self):
        script = """
HUB_URL="http://hub.example:8010"
PLACEHOLDER='__HEIMDALL_HUB''_URL__'
if [ "$HUB_URL" = "$PLACEHOLDER" ]; then
    HUB_URL=""
fi
printf '%s' "$HUB_URL"
"""
        result = subprocess.run(["bash"], input=script, text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, "http://hub.example:8010")

    def test_unreplaced_placeholder_stays_empty(self):
        script = """
HUB_URL="__HEIMDALL_HUB_URL__"
PLACEHOLDER='__HEIMDALL_HUB''_URL__'
if [ "$HUB_URL" = "$PLACEHOLDER" ]; then
    HUB_URL=""
fi
printf '%s' "$HUB_URL"
"""
        result = subprocess.run(["bash"], input=script, text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, "")

    def test_download_list_is_basename_only(self):
        self.assertIsNone(agent_file("../core/server_api.py"))
        self.assertIsNone(agent_file("agent_linux.py/../../core/server_api.py"))
        for name, path in FILES.items():
            self.assertEqual(Path(name).name, name)
            self.assertTrue(path.is_file(), name)


class SettingsTests(unittest.TestCase):
    _KEYS = (
        "SIEM_API_URL",
        "SIEM_API_KEY",
        "SIEM_HOSTNAME",
        "HEIMDALL_HOSTNAME",
        "SIEM_INTERVAL",
        "SIEM_LINUX_INTERVAL",
        "SIEM_AGENT_INTERVAL",
        "SIEM_ROLE",
    )

    def setUp(self):
        self._saved = {key: os.environ.get(key) for key in self._KEYS}
        for key in self._KEYS:
            os.environ.pop(key, None)

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_defaults_match_the_hub_port(self):
        settings = load_settings()
        self.assertEqual(settings.api_url, "http://localhost:8010")
        self.assertGreaterEqual(settings.interval, 5)

    def test_installer_env_is_what_the_agent_reads(self):
        os.environ["SIEM_API_URL"] = "http://hub.example:8010/"
        os.environ["SIEM_API_KEY"] = "secret"
        os.environ["SIEM_HOSTNAME"] = "host-42"
        os.environ["SIEM_INTERVAL"] = "15"
        os.environ["SIEM_ROLE"] = "firewall"
        settings = load_settings(default_interval=30, default_role="linux")
        self.assertEqual(settings.api_url, "http://hub.example:8010")
        self.assertEqual(settings.api_key, "secret")
        self.assertEqual(settings.hostname, "host-42")
        self.assertEqual(settings.interval, 15)
        self.assertEqual(settings.role, "firewall")

    def test_old_interval_name_still_works(self):
        os.environ["SIEM_LINUX_INTERVAL"] = "45"
        settings = load_settings()
        self.assertEqual(settings.interval, 45)

    def test_legacy_hostname_still_works(self):
        os.environ["HEIMDALL_HOSTNAME"] = "legacy-host"
        settings = load_settings()
        self.assertEqual(settings.hostname, "legacy-host")


class RouteTests(unittest.TestCase):
    def test_install_routes_are_public(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from core.agent_install import router

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        linux = client.get("/install/linux")
        self.assertEqual(linux.status_code, 200)
        self.assertIn("http://testserver", linux.text)
        self.assertNotIn(PLACEHOLDER, linux.text)

        runtime = client.get("/install/files/runtime.py")
        self.assertEqual(runtime.status_code, 200)
        self.assertIn("def load_settings", runtime.text)

        missing = client.get("/install/files/not-a-file.py")
        self.assertEqual(missing.status_code, 404)

        windows = client.get("/install/windows")
        self.assertEqual(windows.status_code, 200)
        self.assertIn('[string]$ApiUrl = "http://testserver"', windows.text)


if __name__ == "__main__":
    unittest.main()
