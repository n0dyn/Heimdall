"""
Heimdall - Telegram Alert Module

Sends security alerts to Telegram channel for real-time notifications.
"""

import requests
import os
from datetime import datetime

# Try to import database functions for alert deduplication
try:
    from .database_pg import check_alert_sent, record_alert_sent
    HAS_DB = True
except ImportError:
    HAS_DB = False

# Telegram configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"


def _alert_text(title: str, details: dict, severity: int) -> str:
    """Plain text. Log lines contain characters that break Telegram Markdown."""
    emoji = {
        1: "ℹ️",
        2: "⚠️",
        3: "🟠",
        4: "🔴",
        5: "🚨",
    }.get(severity, "⚠️")
    lines = [f"{emoji} {title}", ""]
    for key, label in (
        ("source_host", "Host"),
        ("os_type", "OS"),
        ("event_type", "Type"),
        ("source_ip", "Source IP"),
        ("user", "User"),
    ):
        value = details.get(key)
        if value:
            lines.append(f"{label}: {value}")
    raw = details.get("raw_message") or ""
    if raw:
        if len(raw) > 2500:
            raw = raw[:2497] + "..."
        lines.extend(["", "Details:", raw])
    when = details.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.extend(["", f"Time: {when}"])
    message = "\n".join(lines)
    if len(message) > 4000:
        message = message[:3997] + "..."
    return message


def _post_telegram(text: str) -> bool:
    response = requests.post(
        TELEGRAM_API_URL,
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
        timeout=10,
    )
    if response.status_code == 200:
        return True
    print(f"Telegram API error: {response.status_code} - {response.text}")
    return False


def send_alert(title: str, details: dict, severity: int = 3) -> bool:
    """
    Send an alert to Telegram channel.

    Args:
        title: Alert title/heading
        details: Dictionary with event details
        severity: Event severity level (1-5)

    Returns:
        bool: True if successful, False otherwise
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram not configured - skipping alert")
        return False

    try:
        return _post_telegram(_alert_text(title, details, severity))
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")
        return False


def send_host_down_alert(hostname: str, os_type: str, last_seen: str) -> bool:
    """Send alert when host goes inactive."""
    # Use hostname as event_id for deduplication
    event_id = f"host-down-{hostname}"

    # Check if already sent to prevent duplicates
    if HAS_DB and check_alert_sent(event_id, "host_down"):
        return False

    details = {
        "source_host": hostname,
        "os_type": os_type,
        "last_seen": last_seen,
        "event_type": "HOST_OFFLINE",
    }
    result = send_alert(f"Host offline: {hostname}", details, severity=4)

    # Record alert if successfully sent
    if result and HAS_DB:
        record_alert_sent(event_id, "host_down")

    return result


def send_critical_event_alert(event: dict) -> bool:
    """Send alert for critical security events."""
    event_id = event.get("event_id", "")

    # Check if already sent to prevent duplicates
    if HAS_DB and event_id and check_alert_sent(event_id, "critical"):
        return False

    title = event.get("event_type", "CRITICAL_EVENT")
    result = send_alert(title, event, severity=event.get("severity", 4))

    # Record alert if successfully sent
    if result and HAS_DB and event_id:
        record_alert_sent(event_id, "critical")

    return result


def send_resource_alert(firing: dict, chat_id: str = None) -> bool:
    """Send a CPU/RAM/disk threshold alert. Optional per-client chat_id."""
    labels = firing.get("labels") or {}
    mount = labels.get("mount")
    extra = f" mount={mount}" if mount else ""
    payload_chat = chat_id or TELEGRAM_CHAT_ID
    title = f"Resource: {firing.get('name')} on {firing.get('source_host')}"
    if not TELEGRAM_BOT_TOKEN or not payload_chat:
        print("Telegram not configured - skipping resource alert")
        return False
    try:
        message = (
            f"🟠 *{title}*\n\n"
            f"🖥️ *Host*: `{firing.get('source_host')}`\n"
            f"📋 *Type*: `SYSTEM_ALERT`\n"
            f"📝 *Details*: `{firing.get('name')}: {firing.get('metric')}="
            f"{float(firing.get('value') or 0):.1f} (threshold {firing.get('threshold')}){extra}`\n"
        )
        resp = requests.post(
            TELEGRAM_API_URL,
            json={"chat_id": payload_chat, "text": message, "parse_mode": "Markdown"},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"Error sending resource alert: {e}")
        return False


def send_docker_run_alert(host: str, events: list) -> bool:
    """One message for a CVE check and the stack update it started."""
    from .docker_logs import describe_docker_run

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram not configured - skipping alert")
        return False
    try:
        return _post_telegram(describe_docker_run(host, events))
    except Exception as e:
        print(f"Error sending Docker run alert: {e}")
        return False


def send_attack_pattern_alert(attacker_ip: str, attempt_count: int) -> bool:
    """Send alert for repeated attack patterns."""
    details = {
        "source_ip": attacker_ip,
        "event_type": "ATTACK_PATTERN",
        "raw_message": f"Multiple failed login attempts detected from {attacker_ip} ({attempt_count} attempts)",
    }
    return send_alert(f"🚨 Attack Pattern Detected: {attacker_ip}", details, severity=4)
