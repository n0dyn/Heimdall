"""
Heimdall Telegram Alerts

Real-time security notifications for Heimdall.
Sends critical alerts, summaries, metrics, and status updates to Telegram.

Instant notification system - keeping you informed when Heimdall detects threats.
"""

import os
import requests
import logging
from datetime import datetime
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)


class TelegramAlert:
    """Send alerts via Telegram bot."""
    
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None):
        """
        Initialize Telegram alerting.
        
        Args:
            bot_token: Telegram bot token (or from TELEGRAM_BOT_TOKEN env var)
            chat_id: Telegram chat/channel ID (or from TELEGRAM_CHAT_ID env var)
        """
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
        self.api_url = "https://api.telegram.org"
        self.enabled = bool(self.bot_token and self.chat_id)
        
        if not self.enabled:
            logger.warning("Telegram alerting disabled (missing BOT_TOKEN or CHAT_ID)")
    
    def _send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """
        Send a message to Telegram.
        
        Args:
            text: Message text
            parse_mode: Message parsing mode (HTML or Markdown)
            
        Returns:
            bool: True if successful
        """
        if not self.enabled:
            return False
        
        try:
            url = f"{self.api_url}/bot{self.bot_token}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.debug("Telegram message sent successfully")
                return True
            else:
                logger.error(f"Telegram error: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"Error sending Telegram message: {e}")
            return False
    
    def alert_critical_event(self, event: Dict) -> bool:
        """
        Send alert for critical security event.
        
        Args:
            event: Event dictionary from database
            
        Returns:
            bool: True if alert sent successfully
        """
        if not self.enabled:
            return False
        
        timestamp = event.get("timestamp", "N/A")
        host = event.get("source_host", "unknown")
        event_type = event.get("event_type", "UNKNOWN")
        severity = event.get("severity", 0)
        user = event.get("user", "system")
        ip = event.get("source_ip", "N/A")
        message = event.get("raw_message", "")
        
        alert_text = f"""
🚨 <b>CRITICAL SECURITY ALERT</b>

<b>Type:</b> {event_type}
<b>Severity:</b> {severity}/5
<b>Host:</b> {host}
<b>User:</b> {user}
<b>Source IP:</b> {ip}
<b>Time:</b> {timestamp}

<b>Details:</b>
<code>{message[:200]}</code>

ID: {event.get('event_id', 'N/A')[:8]}...
"""
        
        return self._send_message(alert_text, "HTML")
    
    def alert_high_events(self, events: List[Dict]) -> bool:
        """
        Send summary alert for multiple high-severity events.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            bool: True if alert sent successfully
        """
        if not self.enabled or not events:
            return False
        
        event_summary = "\n".join([
            f"• <b>{e.get('event_type')}</b> - {e.get('source_host')} @ {e.get('source_ip')}"
            for e in events[:5]
        ])
        
        alert_text = f"""
⚠️ <b>SECURITY ALERTS DETECTED</b>

<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>Count:</b> {len(events)} event(s)

<b>Recent Events:</b>
{event_summary}

{"(and " + str(len(events) - 5) + " more)" if len(events) > 5 else ""}

Check dashboard for details.
"""
        
        return self._send_message(alert_text, "HTML")
    
    def send_metrics_report(self, metrics: Dict) -> bool:
        """
        Send metrics summary report.
        
        Args:
            metrics: Dictionary with metrics data
            
        Returns:
            bool: True if report sent successfully
        """
        if not self.enabled:
            return False
        
        threats_by_os = metrics.get("threats_by_os", {})
        total_alerts = metrics.get("total_alerts_24h", 0)
        top_ips = metrics.get("top_attacking_ips", [])
        
        os_summary = "\n".join([
            f"  • {os_type}: {count}" 
            for os_type, count in threats_by_os.items()
        ])
        
        ips_summary = "\n".join([
            f"  • {ip['ip']}: {ip['count']} events"
            for ip in top_ips[:3]
        ])
        
        report_text = f"""
📊 <b>Mini-SIEM Daily Report</b>

<b>24-Hour Summary:</b>
  Total Alerts: {total_alerts}

<b>Threats by OS:</b>
{os_summary or "  No threats detected"}

<b>Top Attacking IPs:</b>
{ips_summary or "  No attacks detected"}

<b>Most Blocked Domain:</b> {metrics.get('most_blocked_domain', 'N/A')}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return self._send_message(report_text, "HTML")
    
    def send_system_status(self, status: str, details: Optional[str] = None) -> bool:
        """
        Send system status update.
        
        Args:
            status: Status message ("online", "offline", "error", etc.)
            details: Optional additional details
            
        Returns:
            bool: True if message sent successfully
        """
        if not self.enabled:
            return False
        
        status_emoji = {
            "online": "🟢",
            "offline": "🔴",
            "error": "🔴",
            "warning": "🟡",
            "starting": "🟡"
        }.get(status.lower(), "⚪")
        
        msg_text = f"""
{status_emoji} <b>Mini-SIEM Status Update</b>

<b>Status:</b> {status.upper()}
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{details or ""}
"""
        
        return self._send_message(msg_text, "HTML")
    
    def send_agent_status(self, agent_name: str, status: str, last_seen: Optional[str] = None) -> bool:
        """
        Send agent status update.
        
        Args:
            agent_name: Name of the agent
            status: Status ("online", "offline", "error")
            last_seen: Last time agent was seen
            
        Returns:
            bool: True if message sent successfully
        """
        if not self.enabled:
            return False
        
        status_indicator = "✅" if status == "online" else "⚠️" if status == "error" else "❌"
        
        msg_text = f"""
{status_indicator} <b>Agent Status: {agent_name}</b>

<b>Status:</b> {status}
{f"<b>Last Seen:</b> {last_seen}" if last_seen else ""}
<b>Updated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return self._send_message(msg_text, "HTML")
    
    def send_test_message(self) -> bool:
        """
        Send a test message to verify Telegram connection.
        
        Returns:
            bool: True if test message sent successfully
        """
        test_msg = """
🧪 <b>Mini-SIEM Telegram Alert Test</b>

Connection successful! ✅
Your Telegram alerting is configured and working.

This is a test message from your Mini-SIEM system.
You will receive alerts when security events are detected.
"""
        
        return self._send_message(test_msg, "HTML")


class AlertManager:
    """Manages alert thresholds and routing."""
    
    def __init__(self, telegram_alert: Optional[TelegramAlert] = None):
        """
        Initialize alert manager.
        
        Args:
            telegram_alert: TelegramAlert instance
        """
        self.telegram = telegram_alert or TelegramAlert()
        
        # Alert thresholds
        self.critical_threshold = int(os.getenv("ALERT_CRITICAL_THRESHOLD", "5"))
        self.high_threshold = int(os.getenv("ALERT_HIGH_THRESHOLD", "3"))
        
        # Track recent alerts to avoid spam
        self.last_alerts = {}
        self.alert_cooldown = 300  # 5 minutes between similar alerts
    
    def process_event(self, event: Dict) -> bool:
        """
        Process incoming event and trigger alerts if needed.
        
        Args:
            event: Event dictionary from database
            
        Returns:
            bool: True if alert was sent
        """
        severity = event.get("severity", 0)
        event_type = event.get("event_type", "")
        
        # Critical events (severity 5)
        if severity >= 5:
            return self.telegram.alert_critical_event(event)
        
        # High severity events (severity 4)
        # Could implement grouping/batching for high-volume events
        
        return False
    
    def process_metrics(self, metrics: Dict) -> bool:
        """
        Process metrics and send reports.
        
        Args:
            metrics: Metrics dictionary
            
        Returns:
            bool: True if report was sent
        """
        total_alerts = metrics.get("total_alerts_24h", 0)
        
        # Send daily report if there's activity
        if total_alerts > 0:
            return self.telegram.send_metrics_report(metrics)
        
        return False


def test_telegram_connection():
    """Test Telegram connection and configuration."""
    print("🧪 Testing Telegram Connection...\n")
    
    alert = TelegramAlert()
    
    if not alert.enabled:
        print("❌ Telegram not configured")
        print("\nTo enable Telegram alerts, set:")
        print("  export TELEGRAM_BOT_TOKEN=<your_bot_token>")
        print("  export TELEGRAM_CHAT_ID=<your_chat_id>")
        print("\nHow to set up:")
        print("  1. Create bot with @BotFather on Telegram")
        print("  2. Get your chat ID from @userinfobot")
        print("  3. Set environment variables above")
        return False
    
    print("✅ Configuration detected")
    print(f"  Bot Token: {alert.bot_token[:10]}...")
    print(f"  Chat ID: {alert.chat_id}\n")
    
    print("📤 Sending test message...")
    if alert.send_test_message():
        print("✅ Test message sent successfully!")
        print("\nCheck your Telegram for the test message.")
        return True
    else:
        print("❌ Failed to send test message")
        print("Please verify your bot token and chat ID")
        return False


if __name__ == "__main__":
    test_telegram_connection()

