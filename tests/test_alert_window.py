#!/usr/bin/env python3
"""Critical alerts use a time window. Severity under 4 is not sent."""

import inspect
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("SIEM_TEST_MODE", "1")

from core.alert_manager import ALERT_CHECK_INTERVAL_SECONDS, DOCKER_RUN_TIMEOUT, AlertManager
from core import alert_manager as alert_mod
from core.database_pg import _LOG_INSERT, _log_values, get_host_status
from core.docker_logs import describe_docker_run, docker_run_decision, parse_chunk


class TestAlertWindow(unittest.TestCase):
    def test_batch_insert_uses_conflict_do_nothing(self):
        self.assertIn("ON CONFLICT (event_id) DO NOTHING", _LOG_INSERT)
        values = _log_values({
            "event_id": "e1",
            "timestamp": "2026-10-15T00:00:00Z",
            "source_host": "h",
            "os_type": "LINUX",
            "event_type": "LOGIN_FAIL",
            "severity": 3,
            "source_ip": "203.0.113.1",
            "user": "root",
            "raw_message": "x",
            "dest_port": "22",
        })
        self.assertEqual(values[12], 22)

    def test_scan_uses_overlap_and_threshold(self):
        mgr = AlertManager()
        with patch.object(mgr, "get_alerts_enabled", return_value=True), \
             patch.object(mgr, "get_severity_threshold", return_value=4), \
             patch.object(alert_mod, "get_events_since", return_value=[]) as query, \
             patch.object(alert_mod, "get_open_docker_run_events", return_value=[]), \
             patch.object(alert_mod, "send_critical_event_alert") as send:
            mgr.check_critical_events()
        query.assert_called_once_with(ALERT_CHECK_INTERVAL_SECONDS + 30, severity_min=4)
        send.assert_not_called()

    def test_inactive_window_defaults_to_five_minutes(self):
        os.environ.pop("ALERT_INACTIVE_THRESHOLD", None)
        os.environ.pop("ALERT_SEVERITY_THRESHOLD", None)
        mgr = AlertManager()
        with patch.object(alert_mod, "get_config", side_effect=lambda key, default=None: default):
            self.assertEqual(mgr.get_inactive_threshold(), 5)
            self.assertEqual(mgr.get_severity_threshold(), 4)

    def test_unifi_devices_are_not_host_down_candidates(self):
        src = inspect.getsource(get_host_status)
        self.assertIn("h.os_type <> 'UNIFI'", src)
        self.assertIn("l.os_type <> 'UNIFI'", src)

    def test_severity_four_sends_once_and_quiet_hours_do_not(self):
        mgr = AlertManager()
        event = {"event_id": "evt-1", "severity": 4, "event_type": "IDS_ALERT"}
        with patch.object(mgr, "get_alerts_enabled", return_value=True), \
             patch.object(mgr, "get_severity_threshold", return_value=4), \
             patch.object(mgr, "is_quiet_hour", return_value=False), \
             patch.object(alert_mod, "get_events_since", return_value=[event]), \
             patch.object(alert_mod, "get_open_docker_run_events", return_value=[]), \
             patch.object(alert_mod, "check_alert_sent", return_value=False), \
             patch.object(alert_mod, "record_alert_sent", return_value=True), \
             patch.object(alert_mod, "send_critical_event_alert", return_value=True) as send:
            mgr.check_critical_events()
        send.assert_called_once_with(event)

        with patch.object(mgr, "get_alerts_enabled", return_value=True), \
             patch.object(mgr, "get_severity_threshold", return_value=4), \
             patch.object(mgr, "is_quiet_hour", return_value=True), \
             patch.object(alert_mod, "get_events_since", return_value=[event]), \
             patch.object(alert_mod, "get_open_docker_run_events", return_value=[]), \
             patch.object(alert_mod, "check_alert_sent", return_value=False), \
             patch.object(alert_mod, "send_critical_event_alert") as quiet_send:
            mgr.check_critical_events()
        quiet_send.assert_not_called()

    def test_check_once_purges_metrics(self):
        mgr = AlertManager()
        with patch.object(mgr, "check_critical_events"), \
             patch.object(mgr, "check_inactive_hosts"), \
             patch.object(mgr, "check_resource_alerts"), \
             patch.object(alert_mod, "purge_old_metrics", return_value=0) as purge:
            mgr.check_once()
        purge.assert_called_once_with()


def _docker(text, basename):
    return parse_chunk(
        text,
        server_id="docker-test",
        source_host="edge-01",
        source_ip="192.0.2.10",
        user="deploy",
        client_id="default",
        site_id="default",
        basename=basename,
        catchup=False,
    )


class TestDockerRunAlert(unittest.TestCase):
    def test_one_image_failure_keeps_the_build_error(self):
        text = """\
[2026-11-06T11:00:49Z] START app-php
#2 ERROR: pull access denied, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed
ERROR: failed to build: failed to solve: app-php:8.3.36-base: failed to resolve source metadata for docker.io/library/app-php:8.3.36-base: pull access denied, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed
[2026-11-06T11:00:53Z] FAIL app-php: image build failed
"""
        events = _docker(text, "update.log")
        paging = [event for event in events if event["severity"] >= 4]
        self.assertEqual(len(paging), 1)
        self.assertTrue(paging[0]["raw_message"].startswith("FAIL app-php: image build failed"))
        self.assertIn("pull access denied", paging[0]["raw_message"])
        self.assertEqual(paging[0]["raw_message"].count("pull access denied"), 1)

    def test_summary_lists_advisories_and_does_not_page_twice(self):
        text = """\
[2026-11-06T11:00:01Z] ===== CVE check start (dry-run=0) =====
fresh CVE-2026-109258
fresh CVE-2026-109260
[2026-11-06T11:00:49Z] fixable high/critical: 7, new since baseline: 7
[2026-11-06T11:00:49Z] security update needed: new advisory
"""
        events = _docker(text, "cve-check.log")
        paging = [event for event in events if event["severity"] >= 4]
        self.assertEqual(len(paging), 1)
        self.assertIn("CVE-2026-109258", paging[0]["raw_message"])
        self.assertIn("CVE-2026-109260", paging[0]["raw_message"])
        notice = next(event for event in events if event["raw_message"].startswith("security update needed"))
        self.assertEqual(notice["severity"], 1)

    def test_a_closed_run_is_one_message(self):
        now = datetime(2026, 11, 6, 11, 30, tzinfo=timezone.utc)
        events = [
            {
                "event_id": "summary",
                "timestamp": "2026-11-06T11:00:49Z",
                "created_at": now - timedelta(minutes=25),
                "severity": 4,
                "raw_message": "fixable high/critical: 7, new since baseline: 7\nNew advisories:\nCVE-2026-109258",
            },
            {
                "event_id": "fail",
                "timestamp": "2026-11-06T11:00:53Z",
                "created_at": now - timedelta(minutes=25),
                "severity": 4,
                "raw_message": "FAIL app-php: image build failed\npull access denied, repository does not exist",
            },
            {
                "event_id": "done",
                "timestamp": "2026-11-06T11:26:39Z",
                "created_at": now,
                "severity": 4,
                "raw_message": "===== done failures=1 =====",
            },
            {
                "event_id": "exit",
                "timestamp": "2026-11-06T11:26:39Z",
                "created_at": now,
                "severity": 4,
                "raw_message": "updater exited 3; baseline kept so this is retried",
            },
        ]
        action, chosen = docker_run_decision(events, now=now, timeout=DOCKER_RUN_TIMEOUT)
        self.assertEqual(action, "send")
        text = describe_docker_run("edge-01", chosen)
        self.assertIn("CVE-2026-109258", text)
        self.assertIn("app-php: image build failed", text)
        self.assertIn("pull access denied", text)
        self.assertIn("baseline was kept", text)
        self.assertEqual(text.count("app-php"), 1)
        self.assertNotIn("===== done", text)

    def test_an_open_run_waits_and_a_second_closer_is_silent(self):
        now = datetime(2026, 11, 6, 11, 5, tzinfo=timezone.utc)
        open_run = [{
            "event_id": "fail",
            "timestamp": "2026-11-06T11:00:53Z",
            "created_at": now,
            "severity": 4,
            "raw_message": "FAIL app-php: image build failed",
        }]
        action, chosen = docker_run_decision(open_run, now=now, timeout=DOCKER_RUN_TIMEOUT)
        self.assertEqual(action, "wait")
        self.assertEqual(chosen, [])

        closer_only = [{
            "event_id": "exit",
            "timestamp": "2026-11-06T11:26:39Z",
            "created_at": now,
            "severity": 4,
            "raw_message": "updater exited 3; baseline kept so this is retried",
        }]
        action, chosen = docker_run_decision(closer_only, now=now, timeout=DOCKER_RUN_TIMEOUT)
        self.assertEqual(action, "ignore")
        self.assertEqual([event["event_id"] for event in chosen], ["exit"])

    def test_check_sends_one_docker_run_and_still_sends_other_alerts(self):
        mgr = AlertManager()
        ids = {
            "event_id": "evt-9",
            "severity": 4,
            "event_type": "IDS_ALERT",
            "os_type": "LINUX",
        }
        run = [
            {
                "event_id": "fail",
                "source_host": "edge-01",
                "timestamp": "2026-11-06T11:00:53Z",
                "created_at": datetime.now(timezone.utc),
                "severity": 4,
                "os_type": "DOCKER",
                "category": "docker-update",
                "raw_message": "FAIL app-php: image build failed\npull access denied",
            },
            {
                "event_id": "done",
                "source_host": "edge-01",
                "timestamp": "2026-11-06T11:26:39Z",
                "created_at": datetime.now(timezone.utc),
                "severity": 4,
                "os_type": "DOCKER",
                "category": "docker-update",
                "raw_message": "===== done failures=1 =====",
            },
        ]
        with patch.object(mgr, "get_alerts_enabled", return_value=True), \
             patch.object(mgr, "get_severity_threshold", return_value=4), \
             patch.object(mgr, "is_quiet_hour", return_value=False), \
             patch.object(alert_mod, "get_events_since", return_value=[ids, run[0], run[1]]), \
             patch.object(alert_mod, "get_open_docker_run_events", return_value=run), \
             patch.object(alert_mod, "check_alert_sent", return_value=False), \
             patch.object(alert_mod, "record_alert_sent", return_value=True) as recorded, \
             patch.object(alert_mod, "send_critical_event_alert", return_value=True) as single, \
             patch.object(alert_mod, "send_docker_run_alert", return_value=True) as digest:
            mgr.check_critical_events()
        single.assert_called_once_with(ids)
        digest.assert_called_once()
        self.assertEqual(digest.call_args.args[0], "edge-01")
        marked = {call.args[0] for call in recorded.call_args_list}
        self.assertEqual(marked, {"evt-9", "fail", "done"})


if __name__ == "__main__":
    unittest.main()
