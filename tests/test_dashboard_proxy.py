#!/usr/bin/env python3
"""The dashboard HTML must not contain the operator API key."""

import os
import unittest
from pathlib import Path

from ui.dashboard_server import (
    anonymous_console_allowed,
    proxy_client_ip,
    render_index,
    upstream_headers,
)


class TestDashboardProxy(unittest.TestCase):
    def test_render_strips_operator_key(self):
        html = Path(__file__).resolve().parents[1].joinpath("ui/index.html").read_text()
        secret = "super-secret-operator-key"
        html = html.replace("default-insecure-key-change-me", secret)
        rendered = render_index(html)
        self.assertNotIn(secret, rendered)
        self.assertIn("proxy: true", rendered)
        self.assertIn("api_key: ''", rendered)
        self.assertIn("window.location.origin", rendered)

    def test_proxy_strips_api_key_header(self):
        headers = upstream_headers({"api-key": "super-secret-operator-key", "Cookie": "heimdall_session=1"}, "127.0.0.1")
        self.assertNotIn("api-key", {key.lower() for key in headers})
        self.assertNotIn("super-secret-operator-key", " ".join(headers.values()))

    def test_cloudflare_client_ip_ignores_a_prepended_forwarded_for(self):
        headers = {
            "CF-Connecting-IP": "203.0.113.8",
            "X-Forwarded-For": "198.51.100.9, 203.0.113.8",
        }
        previous = os.environ.get("SIEM_TRUST_PROXY")
        os.environ["SIEM_TRUST_PROXY"] = "1"
        try:
            self.assertEqual(proxy_client_ip(headers, "172.18.0.1"), "203.0.113.8")
            self.assertEqual(
                proxy_client_ip({"X-Forwarded-For": "198.51.100.9, 203.0.113.7"}, "172.18.0.1"),
                "203.0.113.7",
            )
        finally:
            if previous is None:
                os.environ.pop("SIEM_TRUST_PROXY", None)
            else:
                os.environ["SIEM_TRUST_PROXY"] = previous

    def test_untrusted_proxy_uses_the_tcp_peer(self):
        previous = os.environ.pop("SIEM_TRUST_PROXY", None)
        try:
            seen = proxy_client_ip(
                {"CF-Connecting-IP": "203.0.113.8", "X-Forwarded-For": "198.51.100.9"},
                "10.1.1.5",
            )
            self.assertEqual(seen, "10.1.1.5")
        finally:
            if previous is not None:
                os.environ["SIEM_TRUST_PROXY"] = previous

    def test_tunnel_header_closes_the_console_before_enrollment(self):
        previous_public = os.environ.pop("SIEM_PUBLIC", None)
        previous_trust = os.environ.pop("SIEM_TRUST_PROXY", None)
        try:
            self.assertTrue(anonymous_console_allowed({}, enrolled=False))
            self.assertFalse(anonymous_console_allowed({"CF-Connecting-IP": "203.0.113.8"}, enrolled=False))
            self.assertFalse(anonymous_console_allowed({}, enrolled=True))
            os.environ["SIEM_TRUST_PROXY"] = "1"
            self.assertFalse(anonymous_console_allowed({}, enrolled=False))
        finally:
            os.environ.pop("SIEM_TRUST_PROXY", None)
            if previous_public is not None:
                os.environ["SIEM_PUBLIC"] = previous_public
            if previous_trust is not None:
                os.environ["SIEM_TRUST_PROXY"] = previous_trust


if __name__ == "__main__":
    unittest.main()
