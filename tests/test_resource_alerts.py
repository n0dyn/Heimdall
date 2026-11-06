#!/usr/bin/env python3
"""Tests for shipped resource-threshold evaluation (not SIEM severity)."""

import unittest
from datetime import datetime, timedelta, timezone

from core.host_metrics import METRIC_CPU, METRIC_DISK, status_to_samples
from core.resource_alerts import (
    DEFAULT_RULES,
    alert_event_id,
    evaluate_rules,
    is_cleared,
    sustained_breach,
)


def series(metric, values, start, host="box-1", step_seconds=60, labels=None):
    rows = []
    for i, val in enumerate(values):
        ts = start + timedelta(seconds=step_seconds * i)
        rows.append({
            "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_host": host,
            "metric": metric,
            "value": val,
            "labels": labels or {},
            "client_id": "default",
        })
    return rows


class TestResourceAlerts(unittest.TestCase):
    def test_cpu_high_fires_after_duration(self):
        now = datetime(2026, 8, 25, 13, 0, tzinfo=timezone.utc)
        start = now - timedelta(minutes=10)
        # 11 samples at 91% covering 10 minutes
        rows = series(METRIC_CPU, [91] * 11, start, step_seconds=60)
        rule = next(r for r in DEFAULT_RULES if r["id"] == "cpu_high")
        self.assertTrue(sustained_breach(rows, rule, now=now))
        firings = evaluate_rules(rows, now=now)
        self.assertTrue(any(f["rule_id"] == "cpu_high" for f in firings))

    def test_brief_spike_does_not_fire(self):
        now = datetime(2026, 8, 25, 13, 0, tzinfo=timezone.utc)
        start = now - timedelta(minutes=10)
        values = [20] * 10 + [99]
        rows = series(METRIC_CPU, values, start, step_seconds=60)
        rule = next(r for r in DEFAULT_RULES if r["id"] == "cpu_high")
        self.assertFalse(sustained_breach(rows, rule, now=now))

    def test_snap_disk_does_not_fire(self):
        now = datetime(2026, 8, 25, 13, 0, tzinfo=timezone.utc)
        start = now - timedelta(minutes=10)
        snap = series(
            METRIC_DISK, [100] * 11, start,
            labels={"mount": "/snap/core24/2124"},
            step_seconds=60,
        )
        firings = evaluate_rules(snap, now=now)
        self.assertFalse(any(f["rule_id"] == "disk_high" for f in firings))

    def test_disk_alert_is_per_mount(self):
        now = datetime(2026, 8, 25, 13, 0, tzinfo=timezone.utc)
        start = now - timedelta(minutes=10)
        root = series(METRIC_DISK, [91] * 11, start, labels={"mount": "/"}, step_seconds=60)
        home = series(METRIC_DISK, [10] * 11, start, labels={"mount": "/home"}, step_seconds=60)
        firings = evaluate_rules(root + home, now=now)
        disk = [f for f in firings if f["rule_id"] == "disk_high"]
        self.assertEqual(len(disk), 1)
        self.assertEqual(disk[0]["labels"]["mount"], "/")

    def test_hysteresis_clear(self):
        now = datetime(2026, 8, 25, 13, 0, tzinfo=timezone.utc)
        rule = next(r for r in DEFAULT_RULES if r["id"] == "cpu_high")
        still_hot = series(METRIC_CPU, [88], now)
        cooled = series(METRIC_CPU, [80], now)
        self.assertFalse(is_cleared(still_hot, rule, now=now))
        self.assertTrue(is_cleared(cooled, rule, now=now))

    def test_event_id_stable(self):
        rule = {"id": "cpu_high", "name": "CPU high"}
        self.assertEqual(
            alert_event_id(rule, "box-1"),
            alert_event_id(rule, "box-1"),
        )
        self.assertNotEqual(
            alert_event_id(rule, "box-1", {"mount": "/"}),
            alert_event_id(rule, "box-1", {"mount": "/var"}),
        )

    def test_siem_events_are_not_required(self):
        # Resource alerts evaluate metric samples, not LogEvent severity.
        samples = status_to_samples({
            "source_host": "box-1",
            "cpu_usage": 12,
            "memory_percent": 12,
            "disk_info": [],
            "timestamp": "2026-08-25T12:00:00Z",
        })
        self.assertFalse(evaluate_rules(samples))


if __name__ == "__main__":
    unittest.main()
