#!/usr/bin/env python3
"""Tests for shipped host metric conversion and time-window query."""

import unittest
from datetime import datetime, timedelta, timezone

from core.host_metrics import (
    METRIC_CPU,
    METRIC_DISK,
    METRIC_MEMORY,
    is_real_disk,
    latest_by_host,
    query_samples,
    status_to_samples,
)


def _status(host="box-1", cpu=10.0, mem=40.0, ts=None, disks=None):
    return {
        "source_host": host,
        "os_type": "LINUX",
        "cpu_usage": cpu,
        "memory_percent": mem,
        "disk_info": disks or [{"mount": "/", "percent": 55.0, "total": 1, "used": 1, "free": 0}],
        "timestamp": ts or "2026-08-25T12:00:00Z",
        "client_id": "acme",
    }


class TestStatusToSamples(unittest.TestCase):
    def test_snap_squashfs_is_not_a_real_disk(self):
        self.assertFalse(is_real_disk({
            "mount": "/snap/core24/2124",
            "fstype": "squashfs",
            "device": "/dev/loop0",
            "percent": 100.0,
        }))
        self.assertTrue(is_real_disk({"mount": "/", "fstype": "ext4", "percent": 80.0}))

    def test_snap_mounts_are_not_sampled(self):
        samples = status_to_samples(_status(disks=[
            {"mount": "/", "percent": 40.0, "fstype": "ext4"},
            {"mount": "/snap/core24/2124", "percent": 100.0, "fstype": "squashfs"},
        ]))
        disk = [s for s in samples if s["metric"] == METRIC_DISK]
        self.assertEqual(len(disk), 1)
        self.assertEqual(disk[0]["labels"]["mount"], "/")

    def test_snapshot_becomes_cpu_mem_disk_samples(self):
        samples = status_to_samples(_status())
        names = {s["metric"] for s in samples}
        self.assertEqual(names, {METRIC_CPU, METRIC_MEMORY, METRIC_DISK})
        cpu = next(s for s in samples if s["metric"] == METRIC_CPU)
        self.assertEqual(cpu["source_host"], "box-1")
        self.assertEqual(cpu["value"], 10.0)
        self.assertEqual(cpu["client_id"], "acme")
        disk = next(s for s in samples if s["metric"] == METRIC_DISK)
        self.assertEqual(disk["labels"]["mount"], "/")

    def test_powershell_shaped_snapshot(self):
        # Shape produced by agents/agent_windows.ps1 Collect-SystemStatus
        status = {
            "source_host": "WIN-CLIENT",
            "os_type": "WINDOWS",
            "cpu_usage": 22.5,
            "cpu_count": 4,
            "memory_total": 8,
            "memory_used": 4,
            "memory_percent": 50.0,
            "disk_info": [{"mount": "C:", "total": 100, "used": 80, "free": 20, "percent": 80.0}],
            "timestamp": "2026-08-25T15:00:00Z",
        }
        samples = status_to_samples(status, client_id="client-a")
        self.assertTrue(any(s["metric"] == METRIC_CPU and s["value"] == 22.5 for s in samples))
        self.assertTrue(
            any(s["metric"] == METRIC_DISK and s["labels"]["mount"] == "C:" and s["value"] == 80.0 for s in samples)
        )
        self.assertTrue(all(s["client_id"] == "client-a" for s in samples))

    def test_query_returns_multiple_points_in_window(self):
        rows = []
        start = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
        for i in range(5):
            ts = start + timedelta(minutes=i)
            rows.extend(status_to_samples(_status(cpu=10 + i, ts=ts.strftime("%Y-%m-%dT%H:%M:%SZ"))))
        points = query_samples(
            rows,
            source_host="box-1",
            metric=METRIC_CPU,
            start="2026-08-25T12:00:00Z",
            end="2026-08-25T12:10:00Z",
        )
        self.assertGreaterEqual(len(points), 2)
        self.assertEqual([p["value"] for p in points], [10.0, 11.0, 12.0, 13.0, 14.0])

    def test_step_downsamples(self):
        rows = []
        start = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
        for i in range(4):
            ts = start + timedelta(seconds=30 * i)
            rows.extend(status_to_samples(_status(cpu=float(i), ts=ts.strftime("%Y-%m-%dT%H:%M:%SZ"))))
        points = query_samples(rows, metric=METRIC_CPU, step_seconds=60)
        self.assertLess(len(points), 4)
        self.assertGreaterEqual(len(points), 1)

    def test_client_isolation_in_query(self):
        a = status_to_samples(_status(host="web-01", cpu=1, ts="2026-08-25T12:00:00Z"))
        b_status = _status(host="web-01", cpu=99, ts="2026-08-25T12:00:00Z")
        b_status["client_id"] = "other"
        b = status_to_samples(b_status)
        points = query_samples(a + b, metric=METRIC_CPU, client_id="acme")
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["value"], 1.0)

    def test_latest_by_host(self):
        rows = status_to_samples(_status(cpu=1, ts="2026-08-25T12:00:00Z"))
        rows += status_to_samples(_status(cpu=9, ts="2026-08-25T12:01:00Z"))
        latest = latest_by_host(rows)
        cpu = [v for v in latest.values() if v["metric"] == METRIC_CPU][0]
        self.assertEqual(cpu["value"], 9.0)


if __name__ == "__main__":
    unittest.main()
