"""
Heimdall Linux Agent

Collects Linux authentication and system logs from /var/log/auth.log or /var/log/secure.
Eyes on Linux systems - monitoring authentications, escalations, and system events.

Supports Debian/Ubuntu and RHEL/CentOS distributions.
"""

import os
import sys
import re
import requests
import json
from datetime import datetime, timezone
import time
import socket
from pathlib import Path
import uuid
import hashlib
from dateutil import tz
import psutil
import platform

# Force unbuffered output for systemd logging
sys.stdout.reconfigure(line_buffering=True)

# Add parent directory to path for imports (optional - try to load, but don't require)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from core.models import LogEvent
    HAVE_CORE_MODELS = True
except ImportError:
    HAVE_CORE_MODELS = False
    # Fallback: just use raw dicts

try:
    from core.host_metrics import is_real_disk
except ImportError:
    def is_real_disk(disk: dict) -> bool:
        mount = str((disk or {}).get("mount") or "")
        fstype = str((disk or {}).get("fstype") or "").lower()
        device = str((disk or {}).get("device") or "")
        if fstype in ("squashfs", "overlay", "tmpfs", "devtmpfs"):
            return False
        if device.startswith("/dev/loop") or "/snap/" in mount or mount.startswith("/snap"):
            return False
        return True

try:
    from runtime import agent_hostname, load_settings
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from runtime import agent_hostname, load_settings


class LinuxAgent:
    """Collects Linux authentication and system logs."""
    
    def __init__(self, api_url: str = "http://localhost:8010", api_key: str = "default-insecure-key-change-me"):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.source_host = agent_hostname()
        self.site_id = os.getenv("SIEM_SITE_ID") or os.getenv("SIEM_SITE") or "default"
        self.os_type = "LINUX"
        self.session = requests.Session()
        self.session.headers.update({"api-key": self.api_key})
        try:
            psutil.cpu_percent(interval=0.05)
        except Exception:
            pass
        
        # Configure log files to monitor
        self.log_files = []
        
        # Check environment variable for custom log files (comma-separated)
        env_logs = os.getenv("SIEM_LOG_FILES")
        if env_logs:
            self.log_files = [f.strip() for f in env_logs.split(",") if f.strip()]
            print(f"[INFO] Configured to monitor: {', '.join(self.log_files)}")
        
        # Default auto-detection if no custom logs specified
        if not self.log_files:
            if Path("/var/log/auth.log").exists():
                self.log_files.append("/var/log/auth.log")  # Debian/Ubuntu
            if Path("/var/log/secure").exists():
                self.log_files.append("/var/log/secure")    # RHEL/CentOS
            # syslog is opt-in via SIEM_LOG_FILES. A catch-all on syslog
            # turns nginx chatter into events and can page Telegram.
            if not self.log_files:
                print("Warning: Could not find standard Linux auth log")
                self.log_files.append("/var/log/auth.log")
        
        state_dir = os.getenv("SIEM_STATE_DIR") or os.getenv("HEIMDALL_STATE_DIR") or "/var/lib/heimdall"
        try:
            Path(state_dir).mkdir(parents=True, exist_ok=True)
            self.state_file = str(Path(state_dir) / "linux_agent_state.json")
        except OSError:
            self.state_file = str(Path(os.getenv("HEIMDALL_LOG_DIR") or ".") / "linux_agent_state.json")
        self.file_states = self._load_state()
        self.processed_lines = set()  # Track processed lines to avoid duplicates
        
        # Regex patterns for event detection
        self.patterns = {
            # Authentication (SSH/System)
            "accepted_login": re.compile(
                r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+",
                re.IGNORECASE
            ),
            "failed_password": re.compile(
                r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ (?P<proto>\S+)",
                re.IGNORECASE
            ),
            "failed_password_invalid": re.compile(
                r"Invalid user (?P<user>\S+) from (?P<ip>\S+)",
                re.IGNORECASE
            ),
            "sudo_auth_fail": re.compile(
                r"sudo:\s+(?P<user>\S+)\s*:\s*(?P<reason>a password is required|authentication failure|user NOT in sudoers|\d+ incorrect password attempts)",
                re.IGNORECASE
            ),
            "sudo_command": re.compile(
                r"(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=(?P<command>.*)",
                re.IGNORECASE
            ),
            "authentication_failure": re.compile(
                r"Authentication failure for (?P<user>\S+) from (?P<ip>\S+)",
                re.IGNORECASE
            ),
            
            # Web Server (Nginx/Apache)
            "web_error_forbidden": re.compile(
                r"(client denied by server configuration|access forbidden|Directory index forbidden|permission denied).*client: (?P<ip>\d+\.\d+\.\d+\.\d+)",
                re.IGNORECASE
            ),
            "web_attack": re.compile(
                r"(UNION SELECT|SELECT.*FROM|<script>|eval\(|/etc/passwd|\.\./\.\.|%00).*(?P<ip>\d+\.\d+\.\d+\.\d+)",
                re.IGNORECASE
            ),
            
            # Email Server (Postfix/Dovecot)
            "postfix_auth_fail": re.compile(
                r"warning: .*\[(?P<ip>\d+\.\d+\.\d+\.\d+)\]: SASL .* authentication failed",
                re.IGNORECASE
            ),
            "dovecot_auth_fail": re.compile(
                r"auth-worker.*\(?,(?P<ip>\d+\.\d+\.\d+\.\d+)\):.*password mismatch",
                re.IGNORECASE
            ),
            
            # System/Kernel
            "oom_kill": re.compile(
                r"(Out of memory: Kill process|oom-killer)",
                re.IGNORECASE
            ),
            
            # Generic System Errors/Warnings
            "kernel_warning": re.compile(
                r"kernel:.*(warn|error|crit|fail|bug|panic|corrupt)",
                re.IGNORECASE
            ),
            "systemd_failure": re.compile(
                r"systemd.*(failed to start|error starting|unit.*failed|emergency mode)",
                re.IGNORECASE
            ),
            # Require the daemon. "docker-compose.yml ... failed" is an nginx 404,
            # and that used to be stored as severity 4 and paged Telegram.
            "docker_error": re.compile(
                r"(dockerd\[|docker daemon).*(error|failed|panic|dead)",
                re.IGNORECASE
            )
        }
    
    def _load_state(self) -> dict:
        """Load the file read positions from state file."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    
                    # Handle legacy state (single int position)
                    if "last_position" in state:
                        print("[INFO] Migrating legacy state format")
                        # Assign old position to the first configured log file
                        if self.log_files:
                            return {self.log_files[0]: state["last_position"]}
                        return {}
                    
                    print(f"[INFO] Loaded state for {len(state)} files")
                    return state
        except Exception as e:
            print(f"[WARN] Could not load state file: {e}")
        return {}

    def _save_state(self):
        """Save the file read positions to state file."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.file_states, f)
        except Exception as e:
            print(f"[ERROR] Could not save state file: {e}")

    def get_file_position(self, file_path):
        """Get current file size for stateful log reading."""
        try:
            return os.path.getsize(file_path)
        except:
            return 0
    
    def read_new_lines(self, file_path: str) -> list[str]:
        """Read only new lines from a specific log file."""
        lines = []
        
        try:
            # Check if file exists and is readable
            if not os.path.exists(file_path):
                return lines
            
            current_size = self.get_file_position(file_path)
            last_pos = self.file_states.get(file_path, 0)
            
            # If file was rotated or size decreased, start from beginning
            if current_size < last_pos:
                last_pos = 0
            
            with open(file_path, 'r', errors='ignore') as f:
                f.seek(last_pos)
                lines = f.readlines()
                self.file_states[file_path] = f.tell()
                self._save_state()  # Save state after reading
        
        except Exception as e:
            print(f"Error reading log file {file_path}: {e}")
        
        return lines
    
    def parse_timestamp(self, line: str) -> str:
        """
        Extract and parse timestamp from log line.
        Handles local timezone conversion to UTC.
        """
        try:
            iso_match = re.match(
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
                line,
            )
            if iso_match:
                raw = iso_match.group(1).replace("Z", "+00:00")
                return datetime.fromisoformat(raw).isoformat()

            # Classic syslog: "Mon DD HH:MM:SS" (no year, no timezone)
            date_match = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
            if date_match:
                date_str = date_match.group(1)
                # Add current year (Linux logs don't include year)
                current_year = datetime.now().year
                dt = datetime.strptime(f"{current_year} {date_str}", "%Y %b %d %H:%M:%S")
                
                # Assign local timezone to naive datetime
                # This fixes the issue where local logs were blindly treated as UTC
                dt_local = dt.replace(tzinfo=tz.tzlocal())
                
                # Return ISO string with local timezone offset (e.g., -05:00)
                # The server/dashboard will handle the conversion/display
                return dt_local.isoformat()
        except Exception as e:
            # print(f"Date parsing error: {e}")
            pass
        
        # Fallback to current UTC time if parsing fails
        return datetime.now(timezone.utc).isoformat()
    
    def parse_event(self, line: str) -> dict:
        """
        Parse a log line and extract relevant information.
        Returns None if the line is not a security event we care about.
        """
        
        # Skip short lines
        if len(line.strip()) < 10:
            return None
        
        # Generate deterministic hash for the line to prevent duplicates
        line_hash = hashlib.md5(line.strip().encode()).hexdigest()
        
        # Get local timezone name for context logging
        try:
            tz_name = datetime.now(tz.tzlocal()).tzname()
        except:
            tz_name = "LOCAL"
            
        # Prepend timezone to message for visibility
        msg_with_tz = f"[{tz_name}] {line.strip()}"

        match = self.patterns["accepted_login"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-login-ok-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "LOGIN_SUCCESS",
                "severity": 1,
                "source_ip": match.group("ip"),
                "user": match.group("user"),
                "raw_message": msg_with_tz
            }

        match = self.patterns["sudo_auth_fail"].search(line)
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
                "raw_message": msg_with_tz
            }

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
                "raw_message": msg_with_tz
            }
        
        # Pattern 2: Invalid user
        match = self.patterns["failed_password_invalid"].search(line)
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
                "raw_message": msg_with_tz
            }
        
        # Pattern 3: Sudo command execution
        if "sudo" in line.lower():
            match = self.patterns["sudo_command"].search(line)
            if match:
                command = match.group("command")
                # Only log if it looks like an actual command (not just sudo setup)
                if "/" in command or "=" not in command[:5]:
                    return {
                        "event_id": f"{self.source_host}-sudo-{line_hash}",
                        "timestamp": self.parse_timestamp(line),
                        "source_host": self.source_host,
                        "os_type": self.os_type,
                        "event_type": "SUDO_ESCALATION",
                        "severity": 2,
                        "source_ip": "N/A",
                        "user": match.group("user"),
                        "raw_message": msg_with_tz
                    }
        
        # Web Server Events
        match = self.patterns["web_error_forbidden"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-web-403-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "CONNECTION_BLOCKED",
                "severity": 2,
                "source_ip": match.group("ip"),
                "user": "www-data",
                "raw_message": msg_with_tz
            }
            
        match = self.patterns["web_attack"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-web-attack-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "WEB_ATTACK",
                "severity": 4,
                "source_ip": match.group("ip"),
                "user": "unknown",
                "raw_message": msg_with_tz
            }

        # Mail Server Events
        if "postfix" in line.lower() or "dovecot" in line.lower():
            match = self.patterns["postfix_auth_fail"].search(line) or self.patterns["dovecot_auth_fail"].search(line)
            if match:
                return {
                    "event_id": f"{self.source_host}-mail-fail-{line_hash}",
                    "timestamp": self.parse_timestamp(line),
                    "source_host": self.source_host,
                    "os_type": self.os_type,
                    "event_type": "LOGIN_FAIL",
                    "severity": 3,
                    "source_ip": match.group("ip"),
                    "user": "mail-user",
                    "raw_message": msg_with_tz
                }

        # System Critical Events
        if self.patterns["oom_kill"].search(line):
            return {
                "event_id": f"{self.source_host}-oom-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "CRITICAL_ERROR",
                "severity": 5,
                "source_ip": "N/A",
                "user": "system",
                "raw_message": msg_with_tz
            }

        # Generic System Alerts
        match = self.patterns["kernel_warning"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-kernel-warn-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "SYSTEM_ALERT",
                "severity": 4, # High Severity
                "source_ip": "N/A",
                "user": "kernel",
                "raw_message": msg_with_tz
            }

        match = self.patterns["systemd_failure"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-systemd-fail-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "SYSTEM_ALERT",
                "severity": 4, # High Severity
                "source_ip": "N/A",
                "user": "systemd",
                "raw_message": msg_with_tz
            }

        match = self.patterns["docker_error"].search(line)
        if match:
            return {
                "event_id": f"{self.source_host}-docker-err-{line_hash}",
                "timestamp": self.parse_timestamp(line),
                "source_host": self.source_host,
                "os_type": self.os_type,
                "event_type": "SYSTEM_ALERT",
                "severity": 4, # High Severity
                "source_ip": "N/A",
                "user": "docker",
                "raw_message": msg_with_tz
            }
        
        return None
    
    def collect_events(self) -> list[dict]:
        """
        Collect recent events from all configured log files.
        Returns a list of parsed events.
        """
        events = []
        
        for log_file in self.log_files:
            try:
                lines = self.read_new_lines(log_file)
                
                for line in lines:
                    # Skip duplicate lines (global dedup across all files)
                    line_hash = hash(line)
                    if line_hash in self.processed_lines:
                        continue
                    
                    self.processed_lines.add(line_hash)
                    
                    parsed = self.parse_event(line)
                    if parsed:
                        events.append(parsed)
            
            except Exception as e:
                print(f"Error collecting events from {log_file}: {e}")
        
        # Clean up processed_lines if it gets too large
        if len(self.processed_lines) > 100000:
            self.processed_lines = set()
        
        return events
    
    def send_events(self, events: list[dict]) -> bool:
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
            
            response = self._post("/ingest", json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                print(f"Sent {result.get('events_processed', 0)} events to API")
                # Explicitly send heartbeat after events to ensure "Last Seen" is updated
                self.send_heartbeat()
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
                "source-host": self.source_host,
                "os-type": self.os_type,
                "source-site": self.site_id,
            }
            
            response = self._post("/heartbeat", headers=headers, timeout=10)
            
            if response.status_code == 200:
                print(f"[INFO] Heartbeat sent to {self.api_url}")
                return True
            else:
                print(f"[WARN] Heartbeat failed: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            print(f"[WARN] Heartbeat error: {e}")
            return False
    
    def collect_system_status(self) -> dict:
        """Collect detailed system status using psutil."""
        try:
            # CPU
            cpu_usage = psutil.cpu_percent(interval=None)
            if cpu_usage is None:
                cpu_usage = 0.0
            cpu_count = psutil.cpu_count()
            
            # Memory
            mem = psutil.virtual_memory()
            
            # Disk (Iterate mounted partitions)
            disk_info = []
            for part in psutil.disk_partitions(all=False):
                try:
                    entry = {
                        "mount": part.mountpoint,
                        "fstype": getattr(part, "fstype", "") or "",
                        "device": getattr(part, "device", "") or "",
                    }
                    if not is_real_disk(entry):
                        continue
                    usage = psutil.disk_usage(part.mountpoint)
                    entry.update({
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                    })
                    disk_info.append(entry)
                except (PermissionError, OSError):
                    continue
            
            # Network
            net_info = []
            interfaces = psutil.net_if_addrs()
            for iface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4 only for now
                        net_info.append({
                            "interface": iface,
                            "ip": addr.address,
                            "mac": "N/A" # psutil handles MAC differently, simplifying for now
                        })
            
            # Processes (Top 10 by CPU)
            top_procs = []
            for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']), 
                               key=lambda p: p.info['cpu_percent'], reverse=True)[:10]:
                top_procs.append(proc.info)
            
            # Boot Time
            boot_time = datetime.fromtimestamp(psutil.boot_time()).isoformat()

            net_io = {}
            try:
                io = psutil.net_io_counters()
                net_io = {"bytes_sent": io.bytes_sent, "bytes_recv": io.bytes_recv}
            except Exception:
                net_io = {}
            
            return {
                "source_host": self.source_host,
                "os_type": self.os_type,
                "site_id": self.site_id,
                "os_details": platform.platform(),
                "cpu_usage": cpu_usage,
                "cpu_count": cpu_count,
                "memory_total": mem.total,
                "memory_used": mem.used,
                "memory_percent": mem.percent,
                "disk_info": disk_info,
                "network_info": net_info,
                "top_processes": top_procs,
                "boot_time": boot_time,
                "net_io": net_io,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            print(f"[ERROR] Collecting system status: {e}")
            return None

    def send_system_status(self) -> bool:
        """Collect and send system status snapshot."""
        try:
            status_data = self.collect_system_status()
            if not status_data:
                return False
                
            payload = {"status": status_data}
            
            response = self._post("/system-status", json=payload, timeout=10)
            
            if response.status_code == 200:
                # print("[INFO] System status sent") # Optional: reduce spam
                return True
            else:
                print(f"[WARN] Failed to send system status: {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Sending system status: {e}")
            return False

    def _post(self, path: str, **kwargs):
        """POST with a short backoff so a brief hub blip does not drop the cycle."""
        url = f"{self.api_url}{path}"
        headers = kwargs.pop("headers", None)
        last_error = None
        for attempt in range(3):
            try:
                response = self.session.post(url, headers=headers, **kwargs)
                if response.status_code >= 500:
                    last_error = f"HTTP {response.status_code}"
                    time.sleep(1.5 * (attempt + 1))
                    continue
                return response
            except requests.RequestException as e:
                last_error = e
                time.sleep(1.5 * (attempt + 1))
        print(f"[WARN] POST {path} failed after retries: {last_error}")
        raise requests.RequestException(str(last_error))

    def run(self, interval: int = 30):
        """
        Main agent loop.
        Collect events and send them to the API at regular intervals.
        """
        print(f"Linux Agent starting (host: {self.source_host} site: {self.site_id})")
        print(f"Log files: {', '.join(self.log_files)}")
        print(f"API URL: {self.api_url}")
        
        while True:
            try:
                # 1. Collect and send Logs
                events = self.collect_events()
                if events:
                    self.send_events(events)
                else:
                    # No new events, just send heartbeat to stay active
                    self.send_heartbeat()
                
                # 2. Collect and send System Status (RMM)
                self.send_system_status()
                
                time.sleep(interval)
            
            except KeyboardInterrupt:
                print("Agent stopped by user")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                time.sleep(interval)


def main():
    """Entry point for the Linux agent."""
    settings = load_settings(default_interval=30, default_role="linux")
    agent = LinuxAgent(api_url=settings.api_url, api_key=settings.api_key)
    agent.run(interval=settings.interval)


if __name__ == "__main__":
    main()