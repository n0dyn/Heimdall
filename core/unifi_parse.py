"""
Normalize UniFi CEF syslog and gateway netfilter lines into LogEvent dicts.

UniFi Network exports Common Event Format over UDP. The same socket also
receives iptables-style gateway lines. This module does not talk to Telegram
or to the network. Severity stays at 1-3 for client and firewall-block noise
so the existing alert threshold (4) does not page on those events.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional


_CEF_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=")
_NETFILTER = re.compile(
    r"SRC=(?P<src>\S+)\s+.*?DST=(?P<dst>\S+)\s+.*?PROTO=(?P<proto>\w+)"
    r"(?:\s+.*?SPT=(?P<spt>\d+))?(?:\s+.*?DPT=(?P<dpt>\d+))?",
    re.IGNORECASE,
)
_ISO_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)
_SYSLOG_TS = re.compile(r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_cef_extension(ext: str) -> dict:
    """Split a CEF extension into keys. Values may contain spaces."""
    if not ext:
        return {}
    matches = list(_CEF_KEY.finditer(ext))
    out = {}
    for i, match in enumerate(matches):
        key = match.group(1)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(ext)
        out[key] = ext[start:end].strip()
    return out


def parse_cef(payload: str) -> Optional[dict]:
    if "CEF:" not in payload:
        return None
    payload = payload[payload.find("CEF:"):]
    body = payload[4:]
    parts = body.split("|", 7)
    if len(parts) < 7:
        return None
    try:
        severity = int(str(parts[6]).strip() or "0")
    except ValueError:
        severity = 0
    return {
        "version": parts[0],
        "vendor": parts[1],
        "product": parts[2],
        "device_version": parts[3],
        "class_id": parts[4],
        "name": parts[5],
        "severity": severity,
        "ext": parse_cef_extension(parts[7] if len(parts) > 7 else ""),
    }


def split_syslog(line: str) -> tuple[str, Optional[str]]:
    text = (line or "").strip()
    text = re.sub(r"^<\d+>", "", text).strip()
    idx = text.find("CEF:")
    if idx >= 0:
        return text[:idx].strip(), text[idx:]
    return text, None


def _timestamp_from_prefix(prefix: str) -> str:
    iso = _ISO_TS.search(prefix or "")
    if iso:
        raw = iso.group(0).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(raw).isoformat()
        except ValueError:
            return raw
    classic = _SYSLOG_TS.search(prefix or "")
    if classic:
        try:
            dt = datetime.strptime(
                f"{datetime.now().year} {classic.group(0)}",
                "%Y %b %d %H:%M:%S",
            )
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_from_prefix(prefix: str) -> str:
    for token in reversed((prefix or "").split()):
        if _ISO_TS.match(token) or _IPV4.match(token):
            continue
        if re.match(r"^[A-Z]{2,5}$", token):
            continue
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", token):
            return token
    return "unifi"


def _event_id(*parts) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _port(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class UnifiNormalizer:
    """Map one syslog line to a Heimdall event dict, or None to drop it."""

    def __init__(self, ingest_clients: bool = False, store_unknown: bool = False):
        self.ingest_clients = ingest_clients
        self.store_unknown = store_unknown

    def normalize(self, line: str) -> Optional[dict]:
        raw = (line or "").strip()
        if len(raw) < 8:
            return None
        prefix, cef_payload = split_syslog(raw)
        if cef_payload:
            parsed = parse_cef(cef_payload)
            if parsed is None:
                return self._unknown(raw, prefix)
            return self._from_cef(parsed, raw, prefix)
        if _NETFILTER.search(raw) and _looks_blocked(raw):
            return self._from_netfilter(raw, prefix)
        return self._unknown(raw, prefix)

    def _from_cef(self, parsed: dict, raw: str, prefix: str) -> Optional[dict]:
        ext = parsed["ext"]
        name = parsed["name"] or ""
        name_l = name.lower()
        category = (ext.get("UNIFIcategory") or "").strip()
        sub = (ext.get("UNIFIsubCategory") or "").strip()
        cat_l = category.lower()
        sub_l = sub.lower()
        host = ext.get("UNIFIhost") or _host_from_prefix(prefix)
        src = ext.get("src") or ext.get("UNIFIclientIp") or ext.get("UNIFIclientIP") or "N/A"
        user = ext.get("UNIFIadmin") or ext.get("suser") or "system"
        ts = _timestamp_from_prefix(prefix)
        event_type, severity, action = _classify(name_l, cat_l, sub_l, parsed["severity"])

        if event_type == "CLIENT_SESSION" and not self.ingest_clients:
            return None

        signature = (
            ext.get("UNIFIthreatType")
            or ext.get("signature")
            or ext.get("signature_id")
            or None
        )
        return {
            # Hash the raw line only. A missing syslog timestamp used to fold
            # in the collector clock, so a UDP retry became a new event and
            # could page Telegram again.
            "event_id": _event_id("cef", raw),
            "timestamp": ts,
            "source_host": host[:200],
            "os_type": "UNIFI",
            "event_type": event_type,
            "severity": severity,
            "source_ip": src,
            "user": (user or "system")[:200],
            "raw_message": raw[:8000],
            "dest_ip": ext.get("dst") or None,
            "dest_port": _port(ext.get("dpt")),
            "protocol": (ext.get("proto") or None),
            "action": action,
            "signature": signature,
            "category": "/".join(p for p in (category, sub) if p) or None,
        }

    def _from_netfilter(self, raw: str, prefix: str) -> dict:
        match = _NETFILTER.search(raw)
        host = _host_from_prefix(prefix) if prefix else "unifi"
        src = match.group("src") if match else "N/A"
        return {
            "event_id": _event_id("netfilter", raw),
            "timestamp": _timestamp_from_prefix(prefix or raw),
            "source_host": host[:200],
            "os_type": "UNIFI",
            "event_type": "CONNECTION_BLOCKED",
            "severity": 2,
            "source_ip": src,
            "user": "system",
            "raw_message": raw[:8000],
            "dest_ip": match.group("dst") if match else None,
            "dest_port": _port(match.group("dpt") if match else None),
            "protocol": match.group("proto") if match else None,
            "action": "blocked",
            "signature": None,
            "category": "Firewall",
        }

    def _unknown(self, raw: str, prefix: str) -> Optional[dict]:
        if not self.store_unknown:
            return None
        return {
            "event_id": _event_id("unknown", raw),
            "timestamp": _timestamp_from_prefix(prefix or raw),
            "source_host": _host_from_prefix(prefix)[:200],
            "os_type": "UNIFI",
            "event_type": "SYSTEM_ALERT",
            "severity": 1,
            "source_ip": "N/A",
            "user": "system",
            "raw_message": raw[:8000],
            "dest_ip": None,
            "dest_port": None,
            "protocol": None,
            "action": None,
            "signature": None,
            "category": None,
        }


def _looks_blocked(line: str) -> bool:
    text = line.lower()
    if any(word in text for word in (" ufw allow", "accepted", " accept ")):
        if not any(word in text for word in ("block", "drop", "deny", "reject")):
            return False
    return any(word in text for word in ("block", "drop", "deny", "reject", "[ufw block]"))


def _classify(name: str, category: str, sub: str, cef_severity: int) -> tuple[str, int, Optional[str]]:
    """Return event_type, Heimdall severity, action."""
    blob = f"{name} {sub} {category}"
    if category == "monitoring" or any(word in name for word in ("client disconnect", "client connected", "roaming", "wifi client")):
        return "CLIENT_SESSION", 1, None
    if "honeypot" in blob:
        return "HONEYPOT", 4, "detected"
    if any(word in blob for word in ("threat", "intrusion", "ids", "ips")):
        severity = 5 if cef_severity >= 9 else 4
        action = "blocked" if "block" in name else "detected"
        return "IDS_ALERT", severity, action
    if "firewall" in sub or "blocked by firewall" in name or (category == "security" and "block" in name):
        return "CONNECTION_BLOCKED", 2, "blocked"
    if "vpn" in blob:
        if any(word in name for word in ("fail", "denied", "invalid")):
            return "LOGIN_FAIL", 4, "denied"
        return "VPN_SESSION", 2, None
    if "admin" in blob or "config" in name:
        return "ADMIN_ACTION", 3, None
    if any(word in blob for word in ("offline", "wan", "failover")):
        return "DEVICE_OFFLINE", 4, None
    return "SYSTEM_ALERT", 1, None
