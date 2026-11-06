#!/usr/bin/env python3
"""The event log shows one row for one docker updater run."""

import unittest
import uuid

from core.docker_logs import collapse_docker_runs


def _row(timestamp, event_type, severity, message, *, host="edge-01",
         os_type="DOCKER", category=None, signature=None, client="default"):
    if category is None and os_type == "DOCKER":
        if message.startswith(("fixable ", "security update", "fresh ")):
            category = "docker-cve"
        else:
            category = "docker-update"
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source_host": host,
        "os_type": os_type,
        "event_type": event_type,
        "severity": severity,
        "source_ip": "192.0.2.10",
        "user": "deploy",
        "raw_message": message,
        "client_id": client,
        "category": category,
        "signature": signature,
    }


# Newest first, as GET /events returns them. Times are the UTC form of the
# 11/06 05:00 CST updater run.
NOV6 = [
    _row("2026-11-06T11:26:39Z", "CRITICAL_ERROR", 4, "===== done failures=3 ====="),
    _row("2026-11-06T11:26:39Z", "CRITICAL_ERROR", 4, "updater exited 3; baseline kept so this is retried"),
    _row("2026-11-06T11:04:40Z", "CRITICAL_ERROR", 4, "FAIL os-patch app-db:16-alpine"),
    _row("2026-11-06T11:04:31Z", "CRITICAL_ERROR", 4, "ERROR: failed to build: failed to solve: Canceled: context canceled"),
    _row("2026-11-06T11:03:40Z", "CRITICAL_ERROR", 4, "FAIL os-patch analytics:postgresql"),
    _row("2026-11-06T11:03:32Z", "CRITICAL_ERROR", 4, "ERROR: failed to build: failed to solve: Canceled: context canceled"),
    _row("2026-11-06T11:00:53Z", "CRITICAL_ERROR", 4, "FAIL app-php: image build failed"),
    _row("2026-11-06T11:00:49Z", "CRITICAL_ERROR", 4, "#2 ERROR: pull access denied, repository does not exist or may require authorization: server message"),
    _row("2026-11-06T11:00:49Z", "SYSTEM_ALERT", 4, "security update needed: new advisory"),
    _row("2026-11-06T11:00:49Z", "VULNERABILITY", 4, "fixable high/critical: 7, new since baseline: 7"),
    _row("2026-11-06T11:00:49Z", "CRITICAL_ERROR", 4, "ERROR: failed to build: failed to solve: app-php:8.3.36-base: failed to resolve source metadata"),
]

NOV4 = [
    _row("2026-11-04T11:00:53Z", "VULNERABILITY", 4, "fixable high/critical: 227, new since baseline: 105"),
    _row("2026-11-04T11:00:53Z", "SYSTEM_ALERT", 4, "security update needed: new advisory"),
]


class TestDockerRunView(unittest.TestCase):
    def test_one_updater_run_is_one_row(self):
        originals = [dict(row) for row in NOV6]
        collapsed = collapse_docker_runs(NOV6)
        self.assertEqual(len(collapsed), 1)
        row = collapsed[0]
        text = row["raw_message"]
        lead = text.splitlines()[0]
        self.assertEqual(
            lead,
            "3 docker update failures. Baseline kept. fixable high/critical: 7, new since baseline: 7",
        )
        self.assertLessEqual(len(lead), 100)
        self.assertIn("app-php: image build failed", text)
        self.assertIn("os-patch analytics:postgresql", text)
        self.assertIn("os-patch app-db:16-alpine", text)
        self.assertIn("pull access denied", text)
        self.assertIn("app-php:8.3.36-base: failed to resolve source metadata", text)
        self.assertEqual(text.count("Canceled: context canceled"), 2)
        self.assertEqual(text.count("pull access denied"), 1)
        self.assertNotIn("===== done", text)
        self.assertNotIn("security update needed", text)
        self.assertNotIn("failed to build:", text)
        self.assertIn("The CVE baseline was kept", text)
        self.assertEqual(row["event_type"], "CRITICAL_ERROR")
        self.assertEqual(row["severity"], 4)
        self.assertEqual(row["timestamp"], "2026-11-06T11:26:39Z")
        self.assertIn(row["event_id"], {item["event_id"] for item in NOV6})
        self.assertEqual([item["raw_message"] for item in NOV6], [item["raw_message"] for item in originals])

    def test_an_older_scan_stays_its_own_row(self):
        collapsed = collapse_docker_runs(NOV6 + NOV4)
        self.assertEqual(len(collapsed), 2)
        self.assertIn("new since baseline: 7", collapsed[0]["raw_message"])
        self.assertNotIn("227", collapsed[0]["raw_message"])
        self.assertEqual(
            collapsed[1]["raw_message"].splitlines()[0],
            "fixable high/critical: 227, new since baseline: 105",
        )
        self.assertNotIn("security update needed", collapsed[1]["raw_message"])
        self.assertEqual(collapsed[1]["event_type"], "VULNERABILITY")
        self.assertNotIn("7, new since baseline: 7", collapsed[1]["raw_message"])

    def test_other_events_keep_their_place(self):
        linux = _row(
            "2026-11-06T12:00:00Z", "IDS_ALERT", 4, "port scan",
            host="neb", os_type="LINUX", category="ids",
        )
        rollback = _row(
            "2026-11-06T11:10:00Z", "CRITICAL_ERROR", 5,
            "rollback failed for heimdall",
        )
        collapsed = collapse_docker_runs([linux] + NOV6[:4] + [rollback] + NOV6[4:])
        self.assertEqual(collapsed[0]["event_id"], linux["event_id"])
        self.assertEqual(collapsed[0]["raw_message"], "port scan")
        self.assertEqual(
            [row["raw_message"] for row in collapsed if "rollback failed" in row["raw_message"]],
            ["rollback failed for heimdall"],
        )
        grouped = [row for row in collapsed if "docker update failures" in row["raw_message"]]
        self.assertEqual(len(grouped), 1)
        self.assertNotIn("rollback failed", grouped[0]["raw_message"])

    def test_a_build_error_already_on_the_fail_line_is_not_repeated(self):
        rows = [
            _row("2026-11-06T11:00:53Z", "CRITICAL_ERROR", 4, "FAIL app-php: image build failed\npull access denied, repository does not exist or may require authorization: server message: insufficient_scope"),
            _row("2026-11-06T11:00:49Z", "CRITICAL_ERROR", 4, "#2 ERROR: pull access denied, repository does not exist or may require authorization: server message"),
        ]
        collapsed = collapse_docker_runs(rows)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["raw_message"].count("pull access denied"), 1)
        self.assertIn("insufficient_scope", collapsed[0]["raw_message"])

    def test_fresh_advisories_are_listed_once(self):
        rows = [
            _row("2026-11-06T11:00:49Z", "VULNERABILITY", 4, "fixable high/critical: 7, new since baseline: 7\nNew advisories:\nCVE-2026-109258"),
            _row("2026-11-06T11:00:49Z", "SYSTEM_ALERT", 1, "security update needed: new advisory"),
            _row("2026-11-06T11:00:10Z", "VULNERABILITY", 3, "fresh CVE-2026-109258", signature="CVE-2026-109258"),
            _row("2026-11-06T11:00:10Z", "VULNERABILITY", 3, "fresh CVE-2026-109260", signature="CVE-2026-109260"),
        ]
        collapsed = collapse_docker_runs(rows)
        self.assertEqual(len(collapsed), 1)
        text = collapsed[0]["raw_message"]
        self.assertEqual(text.count("CVE-2026-109258"), 1)
        self.assertEqual(text.count("CVE-2026-109260"), 1)
        self.assertNotIn("security update needed", text)
        self.assertNotIn("fresh CVE", text)

    def test_a_new_scan_after_a_closer_is_a_second_row(self):
        rows = [
            _row("2026-11-06T14:00:00Z", "VULNERABILITY", 4, "fixable high/critical: 1, new since baseline: 1"),
            _row("2026-11-06T13:30:00Z", "SYSTEM_ALERT", 1, "===== CVE check start (dry-run=0) ====="),
            _row("2026-11-06T12:00:00Z", "CRITICAL_ERROR", 4, "===== done failures=1 ====="),
            _row("2026-11-06T11:00:00Z", "CRITICAL_ERROR", 4, "FAIL heimdall: compose up failed"),
        ]
        collapsed = collapse_docker_runs(rows)
        self.assertEqual(len(collapsed), 2)
        self.assertIn("new since baseline: 1", collapsed[0]["raw_message"])
        self.assertNotIn("heimdall", collapsed[0]["raw_message"])
        self.assertIn("heimdall: compose up failed", collapsed[1]["raw_message"])
        self.assertNotIn("new since baseline: 1", collapsed[1]["raw_message"])

    def test_a_gap_keeps_two_runs_apart(self):
        rows = [
            _row("2026-11-06T18:00:01Z", "CRITICAL_ERROR", 4, "FAIL later: image build failed"),
            _row("2026-11-06T14:00:00Z", "CRITICAL_ERROR", 4, "FAIL earlier: image build failed"),
        ]
        collapsed = collapse_docker_runs(rows)
        self.assertEqual(len(collapsed), 2)
        self.assertTrue(collapsed[0]["raw_message"].startswith("FAIL later"))
        self.assertTrue(collapsed[1]["raw_message"].startswith("FAIL earlier"))

    def test_rows_without_a_category_still_group(self):
        done = _row("2026-11-06T11:01:04Z", "CRITICAL_ERROR", 4, "===== done failures=1 =====", category="")
        fail = _row("2026-11-06T11:01:00Z", "CRITICAL_ERROR", 4, "FAIL heimdall: compose up failed", category="")
        collapsed = collapse_docker_runs([done, fail])
        self.assertEqual(len(collapsed), 1)
        self.assertIn("heimdall: compose up failed", collapsed[0]["raw_message"])
        self.assertNotIn("===== done", collapsed[0]["raw_message"])
        self.assertIn("Baseline kept", collapsed[0]["raw_message"])

    def test_a_different_host_or_organization_stays_separate(self):
        own = _row("2026-11-06T11:00:00Z", "CRITICAL_ERROR", 4, "FAIL heimdall: compose up failed")
        other_host = _row("2026-11-06T11:00:00Z", "CRITICAL_ERROR", 4, "FAIL other: compose up failed", host="other-docker")
        other_org = _row("2026-11-06T11:00:00Z", "CRITICAL_ERROR", 4, "FAIL org: compose up failed", client="other-org")
        collapsed = collapse_docker_runs([own, other_host, other_org])
        self.assertEqual(len(collapsed), 3)
        self.assertEqual(
            [row["raw_message"] for row in collapsed],
            [own["raw_message"], other_host["raw_message"], other_org["raw_message"]],
        )

    def test_grouping_again_does_not_change_the_row(self):
        once = collapse_docker_runs(NOV6 + NOV4)
        twice = collapse_docker_runs(once)
        self.assertEqual(
            [row["raw_message"] for row in twice],
            [row["raw_message"] for row in once],
        )


if __name__ == "__main__":
    unittest.main()
