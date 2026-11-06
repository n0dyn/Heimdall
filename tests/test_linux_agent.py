#!/usr/bin/env python3
"""Linux agent env/site contract (no live log files required)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SIEM_LOG_FILES", "/dev/null")


class TestLinuxAgent(unittest.TestCase):
    def test_hostname_and_site_from_env(self):
        env = {
            "SIEM_HOSTNAME": "client-web-01",
            "SIEM_SITE_ID": "office",
            "SIEM_LOG_FILES": "/dev/null",
            "HEIMDALL_STATE_DIR": tempfile.mkdtemp(),
        }
        with patch.dict(os.environ, env, clear=False):
            from agents.agent_linux import LinuxAgent
            agent = LinuxAgent(api_url="http://hub:8010/", api_key="hk_test")
            self.assertEqual(agent.source_host, "client-web-01")
            self.assertEqual(agent.site_id, "office")
            self.assertEqual(agent.api_url, "http://hub:8010")
            self.assertTrue(agent.state_file.endswith("linux_agent_state.json"))

    def test_status_payload_includes_site(self):
        env = {
            "SIEM_HOSTNAME": "box",
            "SIEM_SITE_ID": "dc1",
            "SIEM_LOG_FILES": "/dev/null",
            "HEIMDALL_STATE_DIR": tempfile.mkdtemp(),
        }
        with patch.dict(os.environ, env, clear=False):
            from agents.agent_linux import LinuxAgent
            agent = LinuxAgent(api_url="http://hub:8010", api_key="hk_test")
            status = {
                "source_host": agent.source_host,
                "site_id": agent.site_id,
                "os_type": "LINUX",
            }
            self.assertEqual(status["site_id"], "dc1")
            self.assertEqual(status["source_host"], "box")

    def test_installer_accepts_site_and_systemd(self):
        text = Path(__file__).resolve().parents[1].joinpath("agents/install_linux_agent.sh").read_text()
        self.assertIn("SIEM_SITE_ID", text)
        self.assertIn("SIEM_HOSTNAME", text)
        self.assertIn("systemd", text)
        self.assertIn("HEIMDALL_STATE_DIR", text)

    def _agent(self):
        env = {
            "SIEM_HOSTNAME": "web-01",
            "SIEM_LOG_FILES": "/dev/null",
            "HEIMDALL_STATE_DIR": tempfile.mkdtemp(),
        }
        with patch.dict(os.environ, env, clear=False):
            from agents.agent_linux import LinuxAgent
            return LinuxAgent(api_url="http://hub:8010", api_key="hk_test")

    def test_iso_publickey_login_is_info(self):
        agent = self._agent()
        line = (
            "2026-10-15T21:08:44.962485+00:00 web-01 sshd[1]: "
            "Accepted publickey for alice from 192.0.2.50 port 43744 ssh2: ED25519 SHA256:test"
        )
        event = agent.parse_event(line)
        self.assertEqual(event["event_type"], "LOGIN_SUCCESS")
        self.assertEqual(event["severity"], 1)
        self.assertEqual(event["user"], "alice")
        self.assertEqual(event["source_ip"], "192.0.2.50")
        self.assertTrue(event["timestamp"].startswith("2026-10-15T21:08:44"))

    def test_classic_failed_password_stays_medium(self):
        agent = self._agent()
        line = "Oct 15 12:00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
        event = agent.parse_event(line)
        self.assertEqual(event["event_type"], "LOGIN_FAIL")
        self.assertEqual(event["severity"], 3)
        self.assertEqual(event["user"], "root")
        self.assertLess(event["severity"], 4)

    def test_sudo_password_required_and_command(self):
        agent = self._agent()
        fail = (
            "2026-10-15T21:08:58.309616+00:00 web-01 sudo:     alice : "
            "a password is required ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/tail"
        )
        failed = agent.parse_event(fail)
        self.assertEqual(failed["event_type"], "LOGIN_FAIL")
        self.assertEqual(failed["severity"], 3)
        self.assertEqual(failed["user"], "alice")

        ok = "Oct 15 12:01:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
        command = agent.parse_event(ok)
        self.assertEqual(command["event_type"], "SUDO_ESCALATION")
        self.assertEqual(command["severity"], 2)

    def test_nginx_compose_404_is_not_an_event(self):
        agent = self._agent()
        line = (
            '2026-04-16T19:15:15+00:00 box nginx: open() '
            '"/home/user-data/www/default/docker-compose.yml" failed (2: No such file)'
        )
        self.assertIsNone(agent.parse_event(line))

    def test_oom_stays_critical(self):
        agent = self._agent()
        line = "Oct 15 12:00:00 host kernel: Out of memory: Kill process 99 (python)"
        event = agent.parse_event(line)
        self.assertEqual(event["event_type"], "CRITICAL_ERROR")
        self.assertEqual(event["severity"], 5)


if __name__ == "__main__":
    unittest.main()
