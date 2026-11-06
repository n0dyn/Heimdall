"""
Heimdall Firewall Agent

Collects firewall logs from multiple sources and sends to Heimdall.
Eyes on your perimeter - watching blocks, scans, and intrusion attempts.

Supports:
- iptables/netfilter (Linux)
- UFW (Uncomplicated Firewall)
- pfSense/OPNsense
- Generic firewall log files

Configurable via FIREWALL_TYPE environment variable.
"""

import os
import sys
import re
import requests
import json
import socket
import time
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from runtime import agent_hostname, load_settings
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from runtime import agent_hostname, load_settings


class FirewallAgent:
    """Collects firewall logs and events."""
    
    def __init__(self, api_url: str = "http://localhost:8000", api_key: str = "default-insecure-key-change-me"):
        self.api_url = api_url
        self.api_key = api_key
        self.source_host = agent_hostname()
        self.os_type = "FIREWALL"
        self.firewall_type = os.getenv("FIREWALL_TYPE", "generic")  # generic, iptables, pfense, etc.
        
        # Log file path - varies by firewall
        self.log_file = self._get_log_file()
        
        self.last_position = 0
        self.processed_lines = set()
        
        # Firewall-specific regex patterns
        self.patterns = self._get_firewall_patterns()
    
    def _get_log_file(self) -> str:
        """Get firewall log file path based on type."""
        override = os.getenv("FIREWALL_LOG_PATH", "").strip()
        if override:
            return override
        fw_type = self.firewall_type.lower()
        
        log_paths = {
            "iptables": "/var/log/kern.log",
            "ufw": "/var/log/ufw.log",
            "pfsense": "/var/log/filter.log",
            "opnsense": "/var/log/filter.log",
            "cisco": "/var/log/syslog",
            "fortinet": "/var/log/syslog",
            "generic": os.getenv("FIREWALL_LOG_PATH", "/var/log/firewall.log")
        }
        
        return log_paths.get(fw_type, log_paths["generic"])
    
    def _get_firewall_patterns(self) -> Dict:
        """Get regex patterns for firewall event detection."""
        return {
            # iptables/netfilter patterns
            "iptables_drop": re.compile(
                r"IN=(?P<in_iface>\S+).*OUT=(?P<out_iface>\S+).*SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\w+).*SPT=(?P<src_port>\d+).*DPT=(?P<dst_port>\d+)",
                re.IGNORECASE
            ),
            # UFW patterns
            "ufw_block": re.compile(
                r"\[UFW BLOCK\].*SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\w+).*SPT=(?P<src_port>\d+).*DPT=(?P<dst_port>\d+)",
                re.IGNORECASE
            ),
            # Generic firewall block pattern
            "generic_block": re.compile(
                r"(?:blocked|denied|dropped).*from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)",
                re.IGNORECASE
            ),
            # Port scan detection
            "port_scan": re.compile(
                r"(?:port\s+scan|syn\s+flood|ddos)",
                re.IGNORECASE
            ),
            # Intrusion attempt
            "intrusion_attempt": re.compile(
                r"(?:intrusion|attack|malicious|threat)",
                re.IGNORECASE
            ),
            # Connection established
            "connection_established": re.compile(
                r"(?:established|connection.*accepted|allowed)",
                re.IGNORECASE
            )
        }
    
    def get_file_position(self) -> int:
        """Get current file size for stateful log reading."""
        try:
            return os.path.getsize(self.log_file)
        except:
            return 0
    
    def read_new_lines(self) -> List[str]:
        """Read only new lines from log file."""
        lines = []
        
        try:
            if not os.path.exists(self.log_file):
                print(f"Warning: Firewall log file not found: {self.log_file}")
                return lines
            
            current_position = self.get_file_position()
            
            # If file was rotated, start from beginning
            if current_position < self.last_position:
                self.last_position = 0
            
            with open(self.log_file, 'r', errors='ignore') as f:
                f.seek(self.last_position)
                lines = f.readlines()
                self.last_position = f.tell()
        
        except Exception as e:
            print(f"Error reading log file: {e}")
        
        return lines
    
    def parse_timestamp(self, line: str) -> str:
        """Extract timestamp from firewall log."""
        try:
            # Try to match common timestamp formats
            timestamp_patterns = [
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",  # ISO format
                r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",  # Syslog format
            ]
            
            for pattern in timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    timestamp_str = match.group(1)
                    # Try to parse
                    try:
                        dt = datetime.fromisoformat(timestamp_str)
                        return dt.replace(tzinfo=timezone.utc).isoformat()
                    except:
                        # Try syslog format
                        current_year = datetime.now().year
                        dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                        return dt.replace(tzinfo=timezone.utc).isoformat()
        except:
            pass
        
        return datetime.now(timezone.utc).isoformat()
    
    def parse_event(self, line: str) -> Optional[Dict]:
        """Parse a firewall log line."""
        
        if len(line.strip()) < 10:
            return None
        
        # Generate deterministic hash for the line to prevent duplicates
        line_hash = hashlib.md5(line.strip().encode()).hexdigest()
        
        # Check for blocked connections
        if "drop" in line.lower() or "block" in line.lower() or "denied" in line.lower():
            match = self.patterns["iptables_drop"].search(line)
            if match:
                return {
                    "event_id": f"{self.source_host}-fw-drop-{line_hash}",
                    "timestamp": self.parse_timestamp(line),
                    "source_host": self.source_host,
                    "os_type": self.os_type,
                    "event_type": "CONNECTION_BLOCKED",
                    "severity": 2,
                    "source_ip": match.group("src_ip"),
                    "user": "firewall",
                    "raw_message": f"Blocked {match.group('proto')} from {match.group('src_ip')}:{match.group('src_port')} to {match.group('dst_ip')}:{match.group('dst_port')}"
                }
            
            # Generic block pattern
            match = self.patterns["generic_block"].search(line)
            if match:
                return {
                    "event_id": f"{self.source_host}-fw-generic-block-{line_hash}",
                    "timestamp": self.parse_timestamp(line),
                    "source_host": self.source_host,
                    "os_type": self.os_type,
                    "event_type": "CONNECTION_BLOCKED",
                    "severity": 2,
                    "source_ip": match.group("src_ip"),
                    "user": "firewall",
                    "raw_message": line.strip()
                }
        
        # Check for port scans
        if self.patterns["port_scan"].search(line):
            # Extract source IP if possible
            src_ip = "N/A"
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                src_ip = ip_match.group(1)
            
            return {
                "event_id": f"{self.source_host}-fw-scan-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "PORT_SCAN",
                "severity": 4,
                "source_ip": src_ip,
                "user": "firewall",
                "raw_message": line.strip()
            }
        
        # Check for intrusion attempts
        if self.patterns["intrusion_attempt"].search(line):
            src_ip = "N/A"
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                src_ip = ip_match.group(1)
            
            return {
                "event_id": f"{self.source_host}-fw-intrusion-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "CRITICAL_ERROR",
                "severity": 5,
                "source_ip": src_ip,
                "user": "firewall",
                "raw_message": line.strip()
            }
        
        return None
    
    def collect_events(self) -> List[Dict]:
        """Collect firewall events."""
        events = []
        
        try:
            lines = self.read_new_lines()
            
            for line in lines:
                line_hash = hash(line)
                if line_hash in self.processed_lines:
                    continue
                
                self.processed_lines.add(line_hash)
                
                parsed = self.parse_event(line)
                if parsed:
                    events.append(parsed)
            
            # Cleanup to prevent memory issues
            if len(self.processed_lines) > 100000:
                self.processed_lines = set()
        
        except Exception as e:
            print(f"Error collecting events: {e}")
        
        return events
    
    def send_events(self, events: List[Dict]) -> bool:
        """Send events to the API."""
        if not events:
            return True
        
        try:
            headers = {"api-key": self.api_key}
            payload = {"events": events}
            
            response = requests.post(
                f"{self.api_url}/ingest",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✓ Sent {result.get('events_processed', 0)} firewall events to API")
                return True
            else:
                print(f"✗ API Error: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"✗ Error sending events: {e}")
            return False

    def send_heartbeat(self) -> bool:
        """Tell the hub this host is still up, even when the log is quiet."""
        try:
            response = requests.post(
                f"{self.api_url}/heartbeat",
                headers={
                    "api-key": self.api_key,
                    "source-host": self.source_host,
                    "os-type": self.os_type,
                },
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def run(self, interval: int = 30):
        """Main agent loop."""
        print(f"Firewall Agent starting (host: {self.source_host})")
        print(f"Firewall Type: {self.firewall_type}")
        print(f"Log File: {self.log_file}")
        print(f"API URL: {self.api_url}")
        
        if not os.path.exists(self.log_file):
            print(f"⚠️  Warning: Log file not found: {self.log_file}")
        
        while True:
            try:
                events = self.collect_events()
                if events:
                    self.send_events(events)
                self.send_heartbeat()

                time.sleep(interval)
            
            except KeyboardInterrupt:
                print("Agent stopped by user")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                time.sleep(interval)


def main():
    """Entry point for firewall agent."""
    settings = load_settings(default_interval=30, default_role="firewall")
    agent = FirewallAgent(api_url=settings.api_url, api_key=settings.api_key)
    agent.run(interval=settings.interval)


if __name__ == "__main__":
    main()

