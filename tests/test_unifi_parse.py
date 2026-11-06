#!/usr/bin/env python3
"""UniFi CEF and gateway syslog normalization. No network, no Telegram."""

import unittest
from unittest.mock import patch

from core.models import LogEvent
from core.unifi_parse import UnifiNormalizer


ADMIN = (
    "CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|"
    "UNIFIcategory=System UNIFIsubCategory=Admin UNIFIhost=Office UDM Pro "
    "UNIFIadmin=Craig src=203.0.113.50 msg=Craig accessed UniFi Network using the web."
)

WIFI = (
    "CEF:0|Ubiquiti|UniFi Network|9.3.33|401|WiFi Client Disconnected|2|"
    "UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIhost=Office UDM Pro "
    "UNIFIclientIp=192.168.10.178 msg=watch disconnected from Employee WiFi."
)

THREAT = (
    "2026-10-15T21:00:00+00:00 gateway CEF:0|Ubiquiti|UniFi Network|9.4.19|201|"
    "Threat Detected and Blocked|7|proto=TCP src=203.0.113.10 spt=52331 "
    "dst=10.0.0.5 dpt=443 UNIFIcategory=Security UNIFIsubCategory=Threat "
    "UNIFIhost=gateway UNIFIthreatType=Malware msg=blocked malware"
)

HONEYPOT = (
    "CEF:0|Ubiquiti|UniFi Network|9.3.33|210|Honeypot Triggered|5|"
    "UNIFIcategory=Security UNIFIsubCategory=Honeypot src=198.51.100.4 UNIFIhost=gateway"
)

FIREWALL = (
    "CEF:0|Ubiquiti|UniFi Network|9.3.33|300|Blocked by Firewall|3|"
    "UNIFIcategory=Security UNIFIsubCategory=Firewall src=198.51.100.8 "
    "dst=10.0.0.9 proto=TCP spt=5555 dpt=22 UNIFIhost=gateway"
)

VPN_FAIL = (
    "CEF:0|Ubiquiti|UniFi Network|9.3.33|610|VPN Authentication Failed|6|"
    "UNIFIcategory=System UNIFIsubCategory=VPN src=203.0.113.8 UNIFIhost=gateway suser=alice"
)

WAN = (
    "CEF:0|Ubiquiti|UniFi Network|9.3.33|710|WAN Failover|5|"
    "UNIFIcategory=Internet UNIFIsubCategory=Failover UNIFIhost=gateway"
)

NETFILTER = (
    "<4>Oct 15 12:00:00 gw kernel: [UFW BLOCK] IN=eth0 OUT= "
    "SRC=203.0.113.5 DST=10.0.0.5 PROTO=TCP SPT=443 DPT=22"
)


class TestUnifiParse(unittest.TestCase):
    def setUp(self):
        self.norm = UnifiNormalizer()

    def test_threat_is_high_and_valid(self):
        event = self.norm.normalize(THREAT)
        LogEvent(**event)
        self.assertEqual(event["event_type"], "IDS_ALERT")
        self.assertEqual(event["severity"], 4)
        self.assertEqual(event["os_type"], "UNIFI")
        self.assertEqual(event["source_host"], "gateway")
        self.assertEqual(event["source_ip"], "203.0.113.10")
        self.assertEqual(event["dest_ip"], "10.0.0.5")
        self.assertEqual(event["dest_port"], 443)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["signature"], "Malware")
        self.assertEqual(event["action"], "blocked")
        again = self.norm.normalize(THREAT)
        self.assertEqual(event["event_id"], again["event_id"])

    def test_cef_id_ignores_collector_clock(self):
        line = (
            "CEF:0|Ubiquiti|UniFi Network|9.3.33|300|Blocked by Firewall|3|"
            "UNIFIcategory=Security UNIFIsubCategory=Firewall src=198.51.100.8 "
            "dst=10.0.0.9 proto=TCP dpt=22 UNIFIhost=gateway"
        )
        with patch(
            "core.unifi_parse._timestamp_from_prefix",
            side_effect=["2026-10-15T21:00:01+00:00", "2026-10-15T21:00:09+00:00"],
        ):
            first = self.norm.normalize(line)
            second = self.norm.normalize(line)
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertNotEqual(first["timestamp"], second["timestamp"])

    def test_wifi_client_is_dropped(self):
        self.assertIsNone(self.norm.normalize(WIFI))
        kept = UnifiNormalizer(ingest_clients=True).normalize(WIFI)
        self.assertEqual(kept["event_type"], "CLIENT_SESSION")
        self.assertEqual(kept["severity"], 1)

    def test_admin_stays_under_telegram_threshold(self):
        event = self.norm.normalize(ADMIN)
        self.assertEqual(event["event_type"], "ADMIN_ACTION")
        self.assertEqual(event["severity"], 3)
        self.assertEqual(event["user"], "Craig")
        self.assertLess(event["severity"], 4)

    def test_honeypot_firewall_vpn_and_wan(self):
        honey = self.norm.normalize(HONEYPOT)
        self.assertEqual(honey["event_type"], "HONEYPOT")
        self.assertEqual(honey["severity"], 4)

        blocked = self.norm.normalize(FIREWALL)
        self.assertEqual(blocked["event_type"], "CONNECTION_BLOCKED")
        self.assertEqual(blocked["severity"], 2)
        self.assertEqual(blocked["dest_port"], 22)

        vpn = self.norm.normalize(VPN_FAIL)
        self.assertEqual(vpn["event_type"], "LOGIN_FAIL")
        self.assertEqual(vpn["severity"], 4)
        self.assertEqual(vpn["user"], "alice")

        wan = self.norm.normalize(WAN)
        self.assertEqual(wan["event_type"], "DEVICE_OFFLINE")
        self.assertEqual(wan["severity"], 4)

    def test_netfilter_block_does_not_page(self):
        event = self.norm.normalize(NETFILTER)
        LogEvent(**event)
        self.assertEqual(event["event_type"], "CONNECTION_BLOCKED")
        self.assertEqual(event["severity"], 2)
        self.assertEqual(event["source_ip"], "203.0.113.5")
        self.assertEqual(event["source_host"], "gw")

    def test_unknown_dropped_unless_asked(self):
        line = "Oct 15 12:00:00 ap hostapd: station associated"
        self.assertIsNone(self.norm.normalize(line))
        kept = UnifiNormalizer(store_unknown=True).normalize(line)
        self.assertEqual(kept["severity"], 1)
        self.assertEqual(kept["event_type"], "SYSTEM_ALERT")

    def test_critical_cef_severity_maps_to_five(self):
        line = THREAT.replace("|7|", "|9|")
        event = self.norm.normalize(line)
        self.assertEqual(event["severity"], 5)


if __name__ == "__main__":
    unittest.main()
