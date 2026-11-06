#!/usr/bin/env python3
"""
Test script for the Mini-SIEM API.
Generates sample events and submits them to the server.
"""

import requests
import json
import os
from datetime import datetime, timedelta
import random

# Configuration
API_URL = os.getenv("SIEM_API_URL", "http://localhost:8000")
API_KEY = os.getenv("SIEM_API_KEY", "default-insecure-key-change-me")

# Sample data
HOSTS = ["web-server-01", "db-server-02", "dns-server", "firewall-01", "ubuntu-desktop", "macos-laptop", "pfsense-gateway"]
LINUX_HOSTS = ["web-server-01", "db-server-02", "ubuntu-desktop"]
WINDOWS_HOSTS = ["firewall-01"]
PIHOLE_HOSTS = ["dns-server"]
MACOS_HOSTS = ["macos-laptop"]
FIREWALL_HOSTS = ["pfsense-gateway"]

SOURCE_IPS = [
    "203.0.113.42",
    "198.51.100.15",
    "192.0.2.88",
    "192.168.1.100",
    "192.168.1.50",
    "10.0.0.45",
    "N/A"
]

USERNAMES = ["admin", "root", "user", "service", "system", "apache", "nginx"]
DOMAINS = [
    "ads.doubleclick.net",
    "tracker.example.com",
    "malicious.site",
    "phishing.domain"
]


def generate_linux_events(count: int = 5) -> list:
    """Generate sample Linux authentication events."""
    events = []
    
    for i in range(count):
        event_type = random.choice(["LOGIN_FAIL", "SUDO_ESCALATION"])
        
        if event_type == "LOGIN_FAIL":
            severity = 3
            message = f"Failed password for {random.choice(USERNAMES)} from {random.choice(SOURCE_IPS[:5])}"
        else:
            severity = 2
            message = f"{random.choice(USERNAMES)} executed sudo command"
        
        events.append({
            "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))).isoformat() + "Z",
            "source_host": random.choice(LINUX_HOSTS),
            "os_type": "LINUX",
            "event_type": event_type,
            "severity": severity,
            "source_ip": random.choice(SOURCE_IPS[:5]),
            "user": random.choice(USERNAMES),
            "raw_message": message
        })
    
    return events


def generate_windows_events(count: int = 3) -> list:
    """Generate sample Windows security events."""
    events = []
    
    event_types = [
        ("LOGIN_FAIL", 3, "Failed Logon"),
        ("ACCOUNT_CREATE", 4, "User Created"),
        ("LOG_TAMPERING", 5, "Log Cleared")
    ]
    
    for i in range(count):
        event_type, severity, message = random.choice(event_types)
        
        events.append({
            "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))).isoformat() + "Z",
            "source_host": random.choice(WINDOWS_HOSTS),
            "os_type": "WINDOWS",
            "event_type": event_type,
            "severity": severity,
            "source_ip": random.choice(SOURCE_IPS[:5]) if event_type == "LOGIN_FAIL" else "N/A",
            "user": random.choice(USERNAMES),
            "raw_message": message
        })
    
    return events


def generate_pihole_events(count: int = 10) -> list:
    """Generate sample Pi-hole DNS blocking events."""
    events = []
    
    for i in range(count):
        domain = random.choice(DOMAINS)
        client_ip = f"192.168.1.{random.randint(50, 200)}"
        
        events.append({
            "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))).isoformat() + "Z",
            "source_host": random.choice(PIHOLE_HOSTS),
            "os_type": "PIHOLE",
            "event_type": "DNS_BLOCK",
            "severity": 1,
            "source_ip": client_ip,
            "user": "pihole",
            "raw_message": f"Blocked DNS query for {domain} from {client_ip}"
        })
    
    return events


def generate_macos_events(count: int = 3) -> list:
    """Generate sample macOS security events."""
    events = []
    
    event_types = [
        ("LOGIN_FAIL", 3, "Failed password for user from 192.168.1.50"),
        ("SUDO_ESCALATION", 2, "Admin executed sudo command"),
        ("CRITICAL_ERROR", 4, "Kernel audit event detected")
    ]
    
    for i in range(count):
        event_type, severity, message = random.choice(event_types)
        
        events.append({
            "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))).isoformat() + "Z",
            "source_host": random.choice(MACOS_HOSTS),
            "os_type": "MACOS",
            "event_type": event_type,
            "severity": severity,
            "source_ip": random.choice(SOURCE_IPS[:5]) if event_type == "LOGIN_FAIL" else "N/A",
            "user": random.choice(USERNAMES),
            "raw_message": message
        })
    
    return events


def generate_firewall_events(count: int = 4) -> list:
    """Generate sample firewall security events."""
    events = []
    
    event_types = [
        ("CONNECTION_BLOCKED", 2, "Blocked connection"),
        ("CONNECTION_BLOCKED", 2, "Denied incoming connection"),
        ("PORT_SCAN", 4, "Port scan detected")
    ]
    
    for i in range(count):
        event_type, severity, message = random.choice(event_types)
        
        events.append({
            "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))).isoformat() + "Z",
            "source_host": random.choice(FIREWALL_HOSTS),
            "os_type": "FIREWALL",
            "event_type": event_type,
            "severity": severity,
            "source_ip": random.choice(SOURCE_IPS[:5]),
            "user": "firewall",
            "raw_message": f"{message} from {random.choice(SOURCE_IPS[:5])} to port {random.randint(1, 65535)}"
        })
    
    return events


def submit_events(events: list) -> bool:
    """Submit events to the API."""
    try:
        headers = {"api-key": API_KEY}
        payload = {"events": events}
        
        print(f"\n📤 Submitting {len(events)} events to {API_URL}/ingest")
        
        response = requests.post(
            f"{API_URL}/ingest",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Success: {result.get('message')}")
            return True
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"   {response.text}")
            return False
    
    except requests.exceptions.ConnectionError:
        print(f"❌ Connection Error: Cannot reach {API_URL}")
        print("   Make sure the server is running: python server_api.py")
        return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


def query_events() -> bool:
    """Query and display recent events."""
    try:
        headers = {"api-key": API_KEY}
        
        print(f"\n📖 Querying events from {API_URL}/events")
        
        response = requests.get(
            f"{API_URL}/events?limit=10",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            events = data.get("events", [])
            
            print(f"\n✅ Retrieved {len(events)} recent events:")
            print("-" * 100)
            
            for event in events[:5]:
                print(f"\n  Host: {event.get('source_host'):<20} | OS: {event.get('os_type'):<10}")
                print(f"  Type: {event.get('event_type'):<20} | Severity: {event.get('severity'):<5}")
                print(f"  User: {event.get('user'):<15} | IP: {event.get('source_ip'):<20}")
                print(f"  Message: {event.get('raw_message')}")
            
            print("\n" + "-" * 100)
            return True
        else:
            print(f"❌ Error: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"❌ Error querying events: {str(e)}")
        return False


def get_metrics() -> bool:
    """Get and display dashboard metrics."""
    try:
        headers = {"api-key": API_KEY}
        
        print(f"\n📊 Fetching metrics from {API_URL}/metrics")
        
        response = requests.get(
            f"{API_URL}/metrics",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print("\n✅ Dashboard Metrics:")
            print("-" * 60)
            print(f"  Total Alerts (24h): {data.get('total_alerts_24h', 0)}")
            
            threats = data.get('threats_by_os', {})
            print(f"  Threats by OS:")
            for os_type, count in threats.items():
                print(f"    - {os_type}: {count}")
            
            top_ips = data.get('top_attacking_ips', [])
            if top_ips:
                print(f"\n  Top 5 Attacking IPs:")
                for item in top_ips[:5]:
                    print(f"    - {item['ip']}: {item['count']} events")
            
            most_blocked = data.get('most_blocked_domain')
            if most_blocked:
                print(f"\n  Most Blocked Domain: {most_blocked}")
            
            print("-" * 60)
            return True
        else:
            print(f"❌ Error: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"❌ Error fetching metrics: {str(e)}")
        return False


def health_check() -> bool:
    """Check API health."""
    try:
        print(f"🏥 Checking API health at {API_URL}/health")
        
        response = requests.get(
            f"{API_URL}/health",
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API is {data.get('status', 'unknown')}")
            return True
        else:
            print(f"❌ API returned status {response.status_code}")
            return False
    
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to API at {API_URL}")
        print("   Make sure the server is running: python server_api.py")
        return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


def main():
    """Main test routine."""
    
    print("=" * 100)
    print("🛡️  Mini-SIEM API Test Script")
    print("=" * 100)
    
    # Check health
    if not health_check():
        return
    
    # Generate and submit sample events
    print("\n" + "=" * 100)
    print("📝 Generating Sample Events")
    print("=" * 100)
    
    linux_events = generate_linux_events(3)
    print(f"\n✓ Generated {len(linux_events)} Linux events")
    
    windows_events = generate_windows_events(2)
    print(f"✓ Generated {len(windows_events)} Windows events")
    
    pihole_events = generate_pihole_events(8)
    print(f"✓ Generated {len(pihole_events)} Pi-hole events")
    
    macos_events = generate_macos_events(3)
    print(f"✓ Generated {len(macos_events)} macOS events")
    
    firewall_events = generate_firewall_events(4)
    print(f"✓ Generated {len(firewall_events)} Firewall events")
    
    # Submit events
    print("\n" + "=" * 100)
    print("🚀 Submitting Events")
    print("=" * 100)
    
    all_events = linux_events + windows_events + pihole_events + macos_events + firewall_events
    submit_events(all_events)
    
    # Query events
    print("\n" + "=" * 100)
    print("📋 Querying Events")
    print("=" * 100)
    
    query_events()
    
    # Get metrics
    print("\n" + "=" * 100)
    print("📊 Dashboard Metrics")
    print("=" * 100)
    
    get_metrics()
    
    print("\n" + "=" * 100)
    print("✅ Test Complete!")
    print("=" * 100)
    print("\nNext steps:")
    print("1. Check the dashboard: http://localhost:8501")
    print("2. View raw events: curl -H 'api-key: {api_key}' http://localhost:8000/events")
    print("3. Read installation: docs/AGENT_INSTALLATION.md")
    print("=" * 100 + "\n")


if __name__ == "__main__":
    main()

