#!/usr/bin/env python3
"""Contract checks for the no-Python Windows agent (agent_windows.ps1)."""

import unittest
from pathlib import Path

from core.host_metrics import METRIC_CPU, METRIC_DISK, METRIC_MEMORY, status_to_samples

REPO = Path(__file__).resolve().parents[1]
PS_AGENT = REPO / "agents" / "agent_windows.ps1"
INSTALLER = REPO / "agents" / "Install-HeimdallAgent.ps1"


class TestWindowsPsAgent(unittest.TestCase):
    def test_agent_script_exists(self):
        self.assertTrue(PS_AGENT.is_file())
        text = PS_AGENT.read_text(encoding="utf-8")
        self.assertGreater(len(text), 500)

    def test_posts_same_api_as_python_agent(self):
        text = PS_AGENT.read_text(encoding="utf-8")
        for path in ("/ingest", "/system-status", "/heartbeat"):
            self.assertIn(path, text)
        self.assertIn("cpu_usage", text)
        self.assertIn("memory_percent", text)
        self.assertIn("disk_info", text)
        self.assertIn("LOGIN_FAIL", text)
        self.assertIn("4625", text)
        self.assertIn("$ProgressPreference = \"SilentlyContinue\"", text)
        self.assertIn("$ApiUrl = $ApiUrl.Trim()", text)
        self.assertIn("agent.env", text)
        self.assertIn("Import-AgentEnv", text)
        self.assertIn("netsh.exe wlan show interfaces", text)
        self.assertNotIn("wlan show networks", text)
        self.assertNotIn("batteryreport", text)
        self.assertIn('kind = "wifi"', text)
        self.assertIn('kind = "endpoint"', text)
        self.assertIn("Win32_Battery", text)
        self.assertIn("Win32_ComputerSystem", text)
        self.assertIn("Win32_EncryptableVolume", text)
        self.assertIn("AntiVirusProduct", text)
        self.assertIn("Confirm-SecureBootUEFI", text)
        self.assertIn("RebootRequired", text)
        self.assertIn("NumberOfLogicalProcessors", text)
        self.assertIn("function ConvertTo-ApiJson", text)
        self.assertIn("-is [datetime]", text)
        self.assertIn("OperationTimeoutSec", text)
        html = (REPO / "ui" / "index.html").read_text(encoding="utf-8")
        self.assertIn("renderEndpointSection", html)
        self.assertIn("row.kind === 'wifi'", html)
        self.assertIn("No wireless adapter", html)

    def test_installer_uses_the_powershell_agent(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("agent_windows.ps1", text)
        self.assertIn("powershell.exe", text)
        self.assertIn("schtasks.exe", text)
        self.assertIn("SIEM_AGENT_INTERVAL", text)
        self.assertIn("HttpWebRequest", text)
        self.assertNotIn("Install-PackagedExe", text)
        self.assertNotIn("Install-PythonAgent", text)
        self.assertNotIn("Python 3.10+", text)
        self.assertNotIn("HeimdallAgent.exe install", text)
        self.assertNotIn("schtasks.exe /End", text)
        self.assertIn("schtasks /End /TN $ServiceName >nul 2>&1", text)
        self.assertNotIn('ApiUrl = "http://localhost:8000"', text)
        self.assertNotIn("Installing as direct Python service (Recommended).", text)

    def test_ps_snapshot_converts_through_shipped_helper(self):
        samples = status_to_samples({
            "source_host": "WIN-NOPYTHON",
            "os_type": "WINDOWS",
            "cpu_usage": 33.0,
            "memory_percent": 44.0,
            "disk_info": [{"mount": "C:", "percent": 70.0}],
            "timestamp": "2026-08-25T12:00:00Z",
        })
        metrics = {s["metric"] for s in samples}
        self.assertEqual(metrics, {METRIC_CPU, METRIC_MEMORY, METRIC_DISK})


if __name__ == "__main__":
    unittest.main()
