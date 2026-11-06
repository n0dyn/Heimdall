"""
Heimdall Pi-hole Agent

Collects blocked DNS queries from Pi-hole FTL database.
Eyes on DNS - watching what's being blocked at the gateway.

Runs on Pi-hole servers to provide direct database access for accurate DNS threat tracking.
"""

import os
import sys
import sqlite3
import requests
import json
from datetime import datetime, timezone
import time
import socket
from pathlib import Path

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


class PiholeAgent:
    """Collects blocked DNS queries from Pi-hole FTL database."""
    
    def __init__(self, api_url: str = "http://localhost:8000", api_key: str = "default-insecure-key-change-me"):
        self.api_url = api_url
        self.api_key = api_key
        self.source_host = agent_hostname()
        self.os_type = "PIHOLE"
        
        # Path to Pi-hole FTL database
        self.pihole_db = os.getenv("SIEM_PIHOLE_DB_PATH", "/etc/pihole/pihole-FTL.db")
        
        # Status codes that represent blocked queries (Pi-hole v5/v6)
        self.blocked_status_codes = [1, 4, 5, 9, 10, 11]
        
        # Track last processed ID to avoid duplicates
        # Initialize with current max ID to prevent re-reading history on restart
        self.last_processed_id = self._get_max_id()
        
        # Verify database exists
        if not os.path.exists(self.pihole_db):
            print(f"Warning: Pi-hole database not found at {self.pihole_db}")
            print("This agent must run on the Pi-hole server")
            
    def _get_max_id(self) -> int:
        """Get the current maximum ID from the Pi-hole database."""
        try:
            if not os.path.exists(self.pihole_db):
                return 0
                
            conn = sqlite3.connect(self.pihole_db)
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM queries")
            result = cursor.fetchone()
            max_id = result[0] if result and result[0] else 0
            conn.close()
            
            print(f"Initialized with last_processed_id = {max_id}")
            return max_id
        except Exception as e:
            print(f"Error getting initial max ID: {e}")
            return 0
    
    def query_blocked_domains(self) -> list[dict]:
        """
        Query blocked DNS queries from the Pi-hole FTL database.
        Returns a list of blocked query records.
        """
        events = []
        
        try:
            conn = sqlite3.connect(self.pihole_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Query blocked queries since last check
            query = """
                SELECT id, timestamp, domain, client, status 
                FROM queries 
                WHERE status IN ({})
                AND id > ?
                ORDER BY id ASC
            """.format(",".join("?" * len(self.blocked_status_codes)))
            
            params = self.blocked_status_codes + [self.last_processed_id]
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            for row in rows:
                event = {
                    "event_id": f"{self.source_host}-pihole-{row['id']}",
                    "timestamp": datetime.fromtimestamp(
                        row['timestamp'], 
                        tz=timezone.utc
                    ).isoformat(),
                    "source_host": self.source_host,
                    "os_type": self.os_type,
                    "event_type": "DNS_BLOCK",
                    "severity": 1,  # Informational - blocked DNS is expected
                    "source_ip": self._sanitize_ip(row['client']),
                    "user": "pihole",
                    "raw_message": f"Blocked DNS query for {row['domain']} from {row['client']} (status: {row['status']})"
                }
                
                events.append(event)
                
                # Update last processed ID
                if row['id'] > self.last_processed_id:
                    self.last_processed_id = row['id']
            
            conn.close()
        
        except sqlite3.OperationalError as e:
            print(f"Database error: {e}")
            print("Make sure this agent is running on the Pi-hole server with database access")
        except Exception as e:
            print(f"Error querying Pi-hole database: {e}")
        
        return events
    
    def _sanitize_ip(self, ip: str) -> str:
        """Sanitize and validate IP address."""
        if not ip:
            return "N/A"
        
        # Remove port if present
        if ":" in ip and not ip.count(":") > 1:  # Not IPv6
            ip = ip.split(":")[0]
        
        return ip if ip else "N/A"
    
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
            
            headers = {"api-key": self.api_key}
            
            response = requests.post(
                f"{self.api_url}/ingest",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"Sent {result.get('events_processed', 0)} blocked DNS queries to API")
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
    
    def run(self, interval: int = 60):
        """
        Main agent loop.
        Poll the Pi-hole database and send blocked queries to the API.
        """
        print(f"Pi-hole Agent starting (host: {self.source_host})")
        print(f"Database: {self.pihole_db}")
        print(f"API URL: {self.api_url}")
        
        # Verify database access on startup
        if not os.path.exists(self.pihole_db):
            print("✗ Cannot access Pi-hole database. Exiting.")
            sys.exit(1)
        
        while True:
            try:
                events = self.query_blocked_domains()
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
    """Entry point for the Pi-hole agent."""
    settings = load_settings(default_interval=60, default_role="pihole")
    agent = PiholeAgent(api_url=settings.api_url, api_key=settings.api_key)
    agent.run(interval=settings.interval)


if __name__ == "__main__":
    main()

