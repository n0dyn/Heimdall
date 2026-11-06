#!/usr/bin/env python3
"""Tests for MSP client/site isolation helpers."""

import unittest

from core.tenancy import (
    ROLE_AGENT,
    ROLE_OPERATOR,
    decorate_org,
    effective_client_id,
    generate_api_key,
    hash_api_key,
    resolve_identity,
    scoped_rows,
    stamp_client,
)


class TestTenancy(unittest.TestCase):
    def test_operator_env_key(self):
        ident = resolve_identity("op-secret", "op-secret", lookup=lambda h: None)
        self.assertEqual(ident["role"], ROLE_OPERATOR)
        self.assertIsNone(ident["client_id"])
        self.assertIsNone(effective_client_id(ident))
        self.assertEqual(effective_client_id(ident, "acme"), "acme")

    def test_agent_site_name_is_prefixed(self):
        ident = {
            "role": ROLE_AGENT,
            "client_id": "acme-1",
            "site_id": "acme-1-default",
        }
        stamped = stamp_client({"source_host": "web-01", "site_id": "office"}, ident)
        self.assertEqual(stamped["client_id"], "acme-1")
        self.assertEqual(stamped["site_id"], "acme-1-office")

    def test_agent_key_cannot_spoof_client(self):
        raw = generate_api_key()
        stored = {
            "role": ROLE_AGENT,
            "client_id": "acme",
            "site_id": "acme-hq",
            "label": "acme agent",
        }
        ident = resolve_identity(raw, "op-secret", lookup=lambda h: stored if h == hash_api_key(raw) else None)
        self.assertEqual(ident["role"], ROLE_AGENT)
        stamped = stamp_client({"source_host": "web-01", "client_id": "other"}, ident)
        self.assertEqual(stamped["client_id"], "acme")
        self.assertEqual(effective_client_id(ident, "other"), "acme")

    def test_unknown_key_rejected(self):
        self.assertIsNone(resolve_identity("nope", "op-secret", lookup=lambda h: None))

    def test_org_workspace_path(self):
        org = decorate_org({"id": "acme-1", "name": "Acme", "slug": "acme-1"})
        self.assertEqual(org["workspace_path"], "/org/acme-1")
        self.assertEqual(org["organization"], "Acme")

    def test_two_clients_same_hostname(self):
        rows = [
            {"source_host": "web-01", "client_id": "acme", "raw_message": "a"},
            {"source_host": "web-01", "client_id": "beta", "raw_message": "b"},
        ]
        acme = scoped_rows(rows, "acme")
        self.assertEqual(len(acme), 1)
        self.assertEqual(acme[0]["raw_message"], "a")
        self.assertEqual(len(scoped_rows(rows, None)), 2)


if __name__ == "__main__":
    unittest.main()
