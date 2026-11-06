#!/usr/bin/env python3
"""Structural checks that the dashboard ships the infrastructure view."""

import unittest
from pathlib import Path

UI = Path(__file__).resolve().parents[1] / "ui" / "index.html"


class TestUiMetricsPage(unittest.TestCase):
    def test_infrastructure_page_and_query_path(self):
        text = UI.read_text(encoding="utf-8")
        self.assertIn('id="page-metrics"', text)
        self.assertIn('data-page="metrics"', text)
        self.assertIn("/metrics/query", text)
        self.assertIn("hostCpuHistoryChart", text)
        self.assertIn("client-switcher", text)
        self.assertIn("site-switcher", text)
        self.assertIn('id="page-clients"', text)
        self.assertIn("Create organization", text)
        self.assertIn("loadMetricsPage", text)
        self.assertIn("/clients/", text)
        self.assertIn("rotate-key", text)
        self.assertIn("window.location.hostname", text)
        self.assertIn("org-picker", text)
        self.assertIn("/org/", text)
        self.assertIn("ORGANIZATION", text)
        self.assertIn("enterOrg", text)
        self.assertIn("history.pushState", text)
        self.assertIn("popstate", text)
        self.assertIn("#/overview/", text)


if __name__ == "__main__":
    unittest.main()
