"""
Heimdall macOS Agent

Collects macOS authentication, system, and audit logs.
Eyes on macOS - watching auth logs, system events, and kernel audits.

Supports macOS 10.12+ systems.
"""

import os
import sys
import re
import requests
import json
import subprocess
from datetime import datetime, timezone
import time
import socket
from pathlib import Path
import uuid
import hashlib

# Add parent directory to path for imports (optional - try to load, but don't require)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from core.models import LogEvent
    HAVE_CORE_MODELS = True
except ImportError:
    HAVE_CORE_MODELS = False
    # Fallback: just use raw dicts

try:
    from runtime import agent_hostname, load_settings
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from runtime import agent_hostname, load_settings


class MacOSAgent:
    """Collects macOS authentication and system logs."""
    
    def __init__(self, api_url: str = "http://localhost:8000", api_key: str = "default-insecure-key-change-me"):
        self.api_url = api_url
        self.api_key = api_key
        self.source_host = agent_hostname()
        self.os_type = "MACOS"
        
        # Log file paths to monitor
        self.log_files = {
            "/var/log/auth.log": "auth",
            "/var/log/system.log": "system",
            "/var/log/install.log": "install"
        }
        
        self.last_position = {}
        self.processed_lines = set()
        
        # Regex patterns for event detection
        self.patterns = {
            "failed_password": re.compile(
                r"Failed password for (?P<user>\S+) from (?P<ip>\S+)",
                re.IGNORECASE
            ),
            "invalid_user": re.compile(
                r"Invalid user (?P<user>\S+) from (?P<ip>\S+)",
                re.IGNORECASE
            ),
            "sudo_command": re.compile(
                r"(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=(?P<command>.*)",
                re.IGNORECASE
            ),
            "sudo_failure": re.compile(
                r"(?P<user>\S+) : authentication failure",
                re.IGNORECASE
            ),
            "user_added": re.compile(
                r"(?P<user>\w+) added to group",
                re.IGNORECASE
            ),
            "sudo_access_denied": re.compile(
                r"(?P<user>\S+) : sorry, you must have a tty to run sudo",
                re.IGNORECASE
            ),
            "kernel_audit": re.compile(
                r"kernel\[.*\]: \*\*\* AUDIT",
                re.IGNORECASE
            )
        }
    
    def get_system_version(self) -> str:
        """Get macOS version."""
        try:
            result = subprocess.run(
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def get_file_position(self, log_file: str) -> int:
        """Get current file size for stateful log reading."""
        try:
            return os.path.getsize(log_file)
        except:
            return 0
    
    def read_new_lines(self, log_file: str) -> list:
        """Read only new lines from log file."""
        lines = []
        
        try:
            if not os.path.exists(log_file):
                return lines
            
            current_position = self.get_file_position(log_file)
            last_position = self.last_position.get(log_file, 0)
            
            # If file was rotated, start from beginning
            if current_position < last_position:
                last_position = 0
            
            with open(log_file, 'r', errors='ignore') as f:
                f.seek(last_position)
                lines = f.readlines()
                self.last_position[log_file] = f.tell()
        
        except Exception as e:
            print(f"Error reading {log_file}: {e}")
        
        return lines
    
    def parse_timestamp(self, line: str) -> str:
        """
        Extract timestamp from macOS log line.
        macOS typically uses: "Month Day HH:MM:SS hostname process[pid]:"
        """
        try:
            # Try to extract standard syslog timestamp
            date_match = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
            if date_match:
                date_str = date_match.group(1)
                current_year = datetime.now().year
                dt = datetime.strptime(f"{current_year} {date_str}", "%Y %b %d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc).isoformat()
        except:
            pass
        
        return datetime.now(timezone.utc).isoformat()
    
    def parse_event(self, line: str, log_type: str) -> dict:
        """
        Parse a macOS log line and extract security events.
        """
        
        if len(line.strip()) < 10:
            return None
        
        # Generate deterministic hash for the line to prevent duplicates
        line_hash = hashlib.md5(line.strip().encode()).hexdigest()
        
        # Pattern 1: Failed password
        match = self.patterns["failed_password"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-failed-pwd-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "LOGIN_FAIL",
                "severity": 3,
                "source_ip": match.group("ip"),
                "user": match.group("user"),
                "raw_message": line.strip()
            }
        
        # Pattern 2: Invalid user
        match = self.patterns["invalid_user"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-invalid-user-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "LOGIN_FAIL",
                "severity": 3,
                "source_ip": match.group("ip"),
                "user": match.group("user"),
                "raw_message": line.strip()
            }
        
        # Pattern 3: Sudo command execution
        if "sudo" in line.lower():
            match = self.patterns["sudo_command"].search(line)
            if match:
                return {
                    "event_id": f"{self.source_host}-sudo-{line_hash}",
                    "timestamp": self.parse_timestamp(line),
                    "source_host": self.source_host,
                    "os_type": self.os_type,
                    "event_type": "SUDO_ESCALATION",
                    "severity": 2,
                    "source_ip": "N/A",
                    "user": match.group("user"),
                    "raw_message": line.strip()
                }
            
            # Sudo failure
            match = self.patterns["sudo_failure"].search(line)
            if match:
                return {
                    "event_id": f"{self.source_host}-sudo-fail-{line_hash}",
                    "timestamp": self.parse_timestamp(line),
                    "source_host": self.source_host,
                    "os_type": self.os_type,
                    "event_type": "LOGIN_FAIL",
                    "severity": 3,
                    "source_ip": "N/A",
                    "user": match.group("user"),
                    "raw_message": line.strip()
                }
        
        # Pattern 4: Kernel audit messages
        if self.patterns["kernel_audit"].search(line):
            return {
                "event_id": f"{self.source_host}-audit-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "CRITICAL_ERROR",
                "severity": 4,
                "source_ip": "N/A",
                "user": "system",
                "raw_message": line.strip()
            }
        
        return None
    
    def collect_events(self) -> list:
        """
        Collect events from macOS log files.
        """
        events = []
        
        try:
            for log_file, log_type in self.log_files.items():
                if not os.path.exists(log_file):
                    continue
                
                lines = self.read_new_lines(log_file)
                
                for line in lines:
                    line_hash = hash(line)
                    if line_hash in self.processed_lines:
                        continue
                    
                    self.processed_lines.add(line_hash)
                    
                    parsed = self.parse_event(line, log_type)
                    if parsed:
                        events.append(parsed)
            
            # Cleanup processed lines to avoid memory buildup
            if len(self.processed_lines) > 100000:
                self.processed_lines = set()
        
        except Exception as e:
            print(f"Error collecting events: {e}")
        
        return events
    
    def send_events(self, events: list) -> bool:
        """Send events to the central API."""
        if not events:
            # Send heartbeat to keep agent active on dashboard
            return self.send_heartbeat()
        
        try:
            if HAVE_CORE_MODELS:
                log_events = [LogEvent(**event) for event in events]
                payload = {"events": [event.model_dump() for event in log_events]}
            else:
                # Use raw dicts if core.models not available
                payload = {"events": events}
            
            headers = {"api-key": self.api_key}
            
            response = requests.post(
                f"{self.api_url}/ingest",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"Sent {result.get('events_processed', 0)} events to API")
                return True
            else:
                print(f"API Error: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            print(f"Error sending events: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send a heartbeat to keep agent marked as active on dashboard."""
        try:
            headers = {
                "api-key": self.api_key,
                "source-host": self.source_host,
                "os-type": self.os_type
            }
            
            response = requests.post(
                f"{self.api_url}/heartbeat",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                # Heartbeat sent silently
                return True
            else:
                return False
        
        except Exception as e:
            # Silently fail on heartbeat
            return False
    
    def collect_system_status(self) -> dict:
        """Collect CPU/RAM/disk snapshot (same schema as Linux/Windows)."""
        try:
            import psutil
        except ImportError:
            print("[WARN] psutil not installed; skipping system status")
            return None
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count() or 1
            mem = psutil.virtual_memory()
            disk_info = []
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_info.append({
                        "mount": part.mountpoint,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                    })
                except (PermissionError, OSError):
                    continue
            net_info = []
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if getattr(addr, "family", None) == socket.AF_INET:
                            net_info.append({"interface": iface, "ip": addr.address, "mac": "N/A"})
            except Exception:
                pass
            top_procs = []
            try:
                for proc in sorted(
                    psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]),
                    key=lambda p: p.info["cpu_percent"] or 0,
                    reverse=True,
                )[:10]:
                    top_procs.append(proc.info)
            except Exception:
                pass
            net_io = {}
            try:
                io = psutil.net_io_counters()
                net_io = {"bytes_sent": io.bytes_sent, "bytes_recv": io.bytes_recv}
            except Exception:
                pass
            return {
                "source_host": self.source_host,
                "os_type": self.os_type,
                "os_details": self.get_system_version() if hasattr(self, "get_system_version") else "macOS",
                "cpu_usage": cpu_usage,
                "cpu_count": cpu_count,
                "memory_total": mem.total,
                "memory_used": mem.used,
                "memory_percent": mem.percent,
                "disk_info": disk_info,
                "network_info": net_info,
                "top_processes": top_procs,
                "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
                "net_io": net_io,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            print(f"[ERROR] Collecting system status: {e}")
            return None

    def send_system_status(self) -> bool:
        status_data = self.collect_system_status()
        if not status_data:
            return False
        try:
            response = requests.post(
                f"{self.api_url}/system-status",
                json={"status": status_data},
                headers={"api-key": self.api_key},
                timeout=10,
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[WARN] system status send failed: {e}")
            return False

    def run(self, interval: int = 30):
        """
        Main agent loop.
        """
        print(f"macOS Agent starting (host: {self.source_host})")
        print(f"macOS Version: {self.get_system_version()}")
        print(f"API URL: {self.api_url}")
        
        while True:
            try:
                events = self.collect_events()
                if events:
                    self.send_events(events)
                self.send_heartbeat()
                self.send_system_status()

                time.sleep(interval)
            
            except KeyboardInterrupt:
                print("Agent stopped by user")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                time.sleep(interval)


def main():
    """Entry point for the macOS agent."""
    settings = load_settings(default_interval=30, default_role="macos")
    agent = MacOSAgent(api_url=settings.api_url, api_key=settings.api_key)
    agent.run(interval=settings.interval)


if __name__ == "__main__":
    # Verify we're on macOS
    if sys.platform != "darwin":
        print("This agent only runs on macOS")
        sys.exit(1)
    
    main()

