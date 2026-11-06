"""
Heimdall - Unified Data Models

Defines the core event schema used across all Heimdall agents and the API.
All security events are normalized into this structure for consistent correlation.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional
from datetime import datetime
import uuid


class LogEvent(BaseModel):
    """
    Heimdall Event Schema
    
    The core event structure that all agents normalize their logs into.
    This unified format enables Heimdall to correlate security events across
    Windows, Linux, macOS, Firewalls, and DNS systems.
    """
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="UUID-v4")
    timestamp: str = Field(..., description="ISO-8601 String (UTC)")
    source_host: str = Field(..., description="e.g., 'ubuntu-server-01'")
    os_type: Literal["WINDOWS", "LINUX", "PIHOLE", "MACOS", "FIREWALL", "UNIFI", "ACTION1", "DOCKER"] = Field(..., description="Operating system or device family")
    event_type: Literal[
        "LOGIN_FAIL",
        "LOGIN_SUCCESS",
        "SUDO_ESCALATION",
        "DNS_BLOCK",
        "CRITICAL_ERROR",
        "ACCOUNT_CREATE",
        "ACCOUNT_DELETE",
        "GROUP_ADD",
        "SERVICE_INSTALL",
        "LOG_TAMPERING",
        "CONNECTION_BLOCKED",
        "PORT_SCAN",
        "PROCESS_EXEC",
        "WEB_ATTACK",
        "SYSTEM_ALERT",
        "IDS_ALERT",
        "HONEYPOT",
        "ADMIN_ACTION",
        "VPN_SESSION",
        "DEVICE_OFFLINE",
        "CLIENT_SESSION",
        "MISSING_UPDATE",
        "VULNERABILITY",
    ] = Field(..., description="Type of security event")
    severity: int = Field(..., ge=1, le=5, description="1=Info, 2=Low, 3=Medium, 4=High, 5=Critical")
    source_ip: str = Field(..., description="IPv4/IPv6 or 'N/A'")
    user: str = Field(..., description="Username or 'system'")
    raw_message: str = Field(..., description="Original log line for context")
    dest_ip: Optional[str] = Field(default=None, description="Destination IP when the source provides one")
    dest_port: Optional[int] = Field(default=None, description="Destination port")
    protocol: Optional[str] = Field(default=None, description="Protocol such as TCP or UDP")
    action: Optional[str] = Field(default=None, description="blocked, detected, allowed")
    signature: Optional[str] = Field(default=None, description="IDS signature or threat name")
    category: Optional[str] = Field(default=None, description="Vendor category, for example Security/Threat")
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2024-01-15T10:30:00Z",
                "source_host": "ubuntu-server-01",
                "os_type": "LINUX",
                "event_type": "LOGIN_FAIL",
                "severity": 3,
                "source_ip": "192.168.1.100",
                "user": "admin",
                "raw_message": "Failed password for admin from 192.168.1.100 port 22 ssh2"
            }
        }


class IngestRequest(BaseModel):
    """Request body for the /ingest endpoint."""
    events: list[LogEvent] = Field(..., description="List of log events to ingest")
    api_key: Optional[str] = Field(None, description="API key for authentication")


class IngestResponse(BaseModel):
    """Response from the /ingest endpoint."""
    success: bool
    message: str
    events_processed: int


class MetricsResponse(BaseModel):
    """Response containing system metrics."""
    total_alerts_24h: int
    threats_by_os: dict
    most_blocked_domain: Optional[str]
    events_per_minute: list[dict]
    top_attacking_ips: list[tuple[str, int]]


class SystemStatus(BaseModel):
    """
    Detailed system status snapshot.
    Used for the RMM (Remote Monitoring) features of Heimdall.
    """
    source_host: str = Field(..., description="Hostname")
    os_type: str = Field(..., description="OS Type")
    os_details: str = Field(..., description="Kernel/Version details")
    
    # Hardware Stats
    cpu_usage: float = Field(..., description="Total CPU usage percent")
    cpu_count: int = Field(..., description="Number of logical cores")
    
    memory_total: int = Field(..., description="Total RAM in bytes")
    memory_used: int = Field(..., description="Used RAM in bytes")
    memory_percent: float = Field(..., description="RAM usage percent")
    
    # Complex Types (will be stored as JSON)
    disk_info: list[dict] = Field(default=[], description="List of partitions")
    network_info: list[dict] = Field(default=[], description="List of interfaces")
    top_processes: list[dict] = Field(default=[], description="Top resource consuming processes")
    
    boot_time: str = Field(..., description="ISO timestamp of last boot")
    timestamp: str = Field(..., description="ISO timestamp of this snapshot")
    net_io: dict = Field(default_factory=dict, description="Optional cumulative network counters")
    client_id: Optional[str] = Field(default=None)
    site_id: Optional[str] = Field(default=None)

    class Config:
        extra = "allow"


class SystemStatusRequest(BaseModel):
    """Request body for status ingestion."""
    status: SystemStatus
    api_key: Optional[str] = Field(None, description="API key")


class MetricSample(BaseModel):
    """One point in the host metric time-series."""
    time: str = Field(..., description="ISO-8601 UTC")
    source_host: str
    client_id: Optional[str] = Field(default="default")
    site_id: Optional[str] = Field(default="default")
    metric: str
    value: float
    labels: dict = Field(default_factory=dict)


class MetricSamplesRequest(BaseModel):
    """Request body for POST /metrics/samples."""
    samples: list[MetricSample] = Field(..., min_length=1)
    api_key: Optional[str] = Field(None, description="API key")


class ClientCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    site_name: Optional[str] = Field(default="default")
    telegram_chat_id: Optional[str] = None


class ClientUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    telegram_chat_id: Optional[str] = None


class SiteCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class SiteUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class EndpointMoveRequest(BaseModel):
    source_host: str = Field(..., min_length=1, max_length=200)
    client_id: str = Field(..., min_length=1, max_length=200)
    destination_client_id: str = Field(..., min_length=1, max_length=200)
    destination_site_id: str = Field(..., min_length=1, max_length=200)

