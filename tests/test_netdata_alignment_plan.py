#!/usr/bin/env python3
"""
Structural checks for the Heimdall vs Netdata alignment analysis.

The shipped artifact is docs/heimdall-netdata-alignment-plan.md (analysis
goal — no collector/schema implementation). This test reads that file and
asserts the gating observations from the goal plan: inventory citations,
snapshot-vs-time-series distinction, five-mechanic mapping, phased SIEM-
preserving plan, MSP isolation, and explicit Netdata deferrals.
"""

from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = REPO_ROOT / "docs" / "heimdall-netdata-alignment-plan.md"

NETDATA_MECHANICS = (
    "Distributed per-node collection of **system/application metrics**",
    "High-resolution **time-series store** and **time-window query**",
    "Auto-generated **real-time metric dashboards**",
    "**Templated health alerts** on those metrics",
    "**Multi-node aggregated view**",
)

REQUIRED_HEIMDALL_CITATIONS = (
    "collect_system_status",
    "psutil",
    "upsert_system_status",
    "last-write-wins",
    "/ingest",
    "/events",
    "events_per_minute",
    "updateHostModalWithRMM",
    "alert_manager.py",
    "send_host_down_alert",
    "TELEGRAM",
)

REQUIRED_PHASE_MARKERS = (
    "Phase 1",
    "Phase 2",
    "Phase 3",
    "Time-series host metrics",
    "Metric dashboards",
    "Resource-threshold alerts",
    "Client / site isolation",
)

REQUIRED_DEFERRALS = (
    "800+ collectors",
    "C dbengine",
    "Unsupervised per-metric ML",
    "Netdata Cloud",
    "1-second C-agent rewrite",
)


def _load_plan() -> str:
    if not PLAN_PATH.is_file():
        raise FileNotFoundError(f"missing analysis artifact: {PLAN_PATH}")
    return PLAN_PATH.read_text(encoding="utf-8")


class TestNetdataAlignmentPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = _load_plan()

    def test_artifact_is_nonempty_markdown(self):
        self.assertGreater(len(self.text.strip()), 2000)
        self.assertTrue(self.text.lstrip().startswith("#"))

    def test_snapshot_versus_time_series_distinction(self):
        lower = self.text.lower()
        self.assertIn("last-write-wins", lower)
        self.assertIn("not a queryable time-series of metrics", lower)
        self.assertIn("system_status", self.text)
        self.assertIn("UNIQUE", self.text)

    def test_heimdall_inventory_citations(self):
        for token in REQUIRED_HEIMDALL_CITATIONS:
            with self.subTest(token=token):
                self.assertIn(token, self.text)

    def test_five_netdata_mechanics_mapped(self):
        # Mapping table rows carry present/partial/absent tags plus evidence.
        for mechanic in NETDATA_MECHANICS:
            with self.subTest(mechanic=mechanic):
                self.assertIn(mechanic, self.text)
        # Each of the five rows in §3 must be tagged; require all three
        # tags exist and the two fully-absent mechanics are labeled Absent.
        self.assertIn("| **Partial** |", self.text)
        self.assertIn("| **Absent** |", self.text)
        # Mapping table puts status in the cell after the mechanic name.
        self.assertRegex(
            self.text,
            r"time-series store.*\|\s*\*\*Absent\*\*",
        )
        self.assertRegex(
            self.text,
            r"Templated health alerts.*\|\s*\*\*Absent\*\*",
        )

    def test_phased_plan_keeps_siem_and_names_alignment_work(self):
        self.assertIn("SIEM", self.text)
        self.assertIn("`LogEvent`", self.text)
        self.assertIn("first-class", self.text.lower())
        for marker in REQUIRED_PHASE_MARKERS:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.text)

    def test_explicit_deferral_section(self):
        self.assertIn("## 5. Explicitly deferred Netdata polish", self.text)
        for item in REQUIRED_DEFERRALS:
            with self.subTest(item=item):
                self.assertIn(item, self.text)

    def test_msp_client_site_isolation_in_scope(self):
        lower = self.text.lower()
        self.assertIn("client_id", self.text)
        self.assertIn("site", lower)
        self.assertIn("per-client", lower)
        self.assertIn("consulting", lower)


if __name__ == "__main__":
    unittest.main()
