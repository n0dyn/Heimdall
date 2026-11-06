"""
Heimdall - REST API Server

Central API hub for the Heimdall security monitoring platform.
Handles event ingestion from all agents, validation, storage, and analytics queries.

Heimdall stands guard with a comprehensive REST API for security intelligence.
"""

from fastapi import FastAPI, HTTPException, Header, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
from datetime import datetime, timedelta

from .operator_auth import (
    RequestScopeMiddleware,
    agent_read_blocked,
    assert_public_config,
    current_request,
    ensure_operator_bootstrap,
    network_operator_write,
    operator_key_allowed,
    public_mode,
)
from .auth_routes import (
    api_key_locked,
    note_api_key_failure,
    router as auth_router,
    session_identity_for_gate,
)

# Try to load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, proceed without it
    pass

from .models import (
    LogEvent, IngestRequest, IngestResponse, MetricsResponse, SystemStatusRequest,
    MetricSamplesRequest, ClientCreateRequest, ClientUpdateRequest,
    SiteCreateRequest, SiteUpdateRequest, EndpointMoveRequest,
)
from .docker_logs import collapse_docker_runs
from .database_pg import (
    init_database, insert_event, insert_events_batch, get_all_events, get_events_by_filter,
    get_metrics_24h, get_top_attacking_ips, get_events_per_minute, get_host_status,
    record_heartbeat, remove_monitored_host, get_config, set_config,
    upsert_system_status, get_system_status, insert_metric_samples, query_host_metrics,
    get_all_system_status, lookup_api_key, create_client, insert_api_key, list_clients,
    get_client, list_alert_rules, update_client, delete_client, list_sites, create_site,
    update_site, delete_site, delete_api_keys_for_client, get_site,
)
from .alert_manager import start_alert_manager
from .host_metrics import status_to_samples, latest_by_host, DEFAULT_CLIENT_ID
from .tenancy import (
    resolve_identity, effective_client_id, effective_site_id, stamp_client, ROLE_OPERATOR,
    generate_api_key, hash_api_key, key_prefix, site_belongs_to_client,
)
from .placement import lookup_placement, move_endpoint, PlacementError
from .action1_client import REGION_LABELS, Action1Error
from .action1_deploy import AgentDeployRequest, deploy_agents
from .action1_sync import (
    action1_state, link_organization, refresh_organizations, remove_remote_endpoint,
    save_settings, sync_action1, unlink_organization,
)
from .agent_install import router as install_router

# Configuration - load from environment variables with sensible defaults
API_KEY = os.getenv("SIEM_API_KEY", "default-insecure-key-change-me")
DATABASE_PATH = os.getenv("SIEM_DATABASE_PATH", "mini_siem.db")
VALID_API_KEYS = {API_KEY}
TEST_MODE = os.getenv("SIEM_TEST_MODE", "").lower() in ("1", "true", "yes")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and start background services on startup."""
    if not TEST_MODE:
        init_database()
        try:
            from .unifi_key import ensure_unifi_agent_key
            ensure_unifi_agent_key()
        except Exception as e:
            print(f"UniFi agent key setup failed: {e}")
        assert_public_config(API_KEY)
        try:
            from .auth_store import get_store
            ensure_operator_bootstrap(get_store().get_secret("enrolled") == "1")
        except Exception as e:
            print(f"Operator enrollment setup failed: {e}")
        start_alert_manager()
        try:
            from .docker_collect import start_docker_collector
            start_docker_collector()
        except Exception as e:
            print(f"Docker log collector setup failed: {e}")
    yield


_docs_url = None if public_mode() else "/docs"
_openapi_url = None if public_mode() else "/openapi.json"
app = FastAPI(
    title="Heimdall API",
    description="Heimdall - Standing Guard Over Your Infrastructure. Central event ingestion and security intelligence API.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=None if public_mode() else "/redoc",
    openapi_url=_openapi_url,
)

# RequestScope must be the innermost middleware. CORS uses a child task, and a
# context set outside that task is invisible to the endpoint.
app.add_middleware(RequestScopeMiddleware)
# Browser calls go through the dashboard on the same origin. A wildcard with
# credentials would let any site ride a stolen cookie, so cross-origin is
# limited to the configured public origin.
_public_origin = os.getenv("SIEM_ORIGIN", "").strip().rstrip("/")
if _public_origin:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[_public_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "api-key"],
    )
app.include_router(auth_router)

app.include_router(install_router)


def validate_api_key(api_key: str = Header(None)):
    """Operator-only gate for alert settings, host delete, and Telegram config."""
    identity = require_identity(api_key)
    require_operator(identity)
    return identity


def require_identity(api_key: str = None) -> dict:
    """Session for humans. Agent keys for collectors. Operator env key only on loopback."""
    request = current_request()
    session_identity = session_identity_for_gate()
    if session_identity is not None:
        if session_identity.get("limited"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Finish account recovery before using the console",
            )
        return session_identity
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key"
        )
    if api_key_locked(request):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Wait 15 minutes.",
        )
    ident = resolve_identity(api_key, API_KEY, lookup_api_key)
    if ident is None:
        note_api_key_failure(request)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    if ident.get("role") == ROLE_OPERATOR and not operator_key_allowed(request):
        if not network_operator_write(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operator key is not accepted from the network. Sign in at the dashboard.",
            )
    if ident.get("role") != ROLE_OPERATOR and agent_read_blocked(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent credentials cannot read data while Heimdall is in public mode.",
        )
    return ident


def require_operator(identity: dict):
    if identity.get("role") != ROLE_OPERATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator API key required"
        )


def stamp_ingested(record: dict, identity: dict) -> dict:
    """Stamp tenancy, then honor an endpoint move for later agent writes."""
    return stamp_client(record, identity, placement_for=lookup_placement)


@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "message": "Mini-SIEM API is running",
        "version": "1.0.0"
    }


@app.post("/ingest", response_model=IngestResponse, tags=["Ingestion"])
async def ingest_logs(request: IngestRequest, api_key: str = Header(None)):
    """
    Ingest log events from agents.

    The request must include an API key header for authentication.
    All events must conform to the unified data schema.
    """

    identity = require_identity(api_key)

    try:
        # Convert events to dictionaries for batch insertion
        event_dicts = [stamp_ingested(event.model_dump(), identity) for event in request.events]

        # Use batch insert for better performance
        processed, failed = insert_events_batch(event_dicts)

        # Agents that push events are treated as alive. UniFi syslog names the
        # gateway or AP as source_host and those devices never send /heartbeat.
        # Action1 inventory and docker-update logs must not heartbeat either.
        # Recording one would mark them down after the inactive window and page Telegram.
        if processed > 0:
            seen = set()
            for d in event_dicts:
                if d.get("os_type") in ("UNIFI", "ACTION1", "DOCKER"):
                    continue
                key = (d.get("source_host"), d.get("os_type"))
                if key in seen:
                    continue
                seen.add(key)
                try:
                    record_heartbeat(
                        d["source_host"], d["os_type"],
                        client_id=d.get("client_id") or DEFAULT_CLIENT_ID,
                        site_id=d.get("site_id"),
                    )
                except Exception as e:
                    print(f"Failed to update implicit heartbeat for {d.get('source_host')}: {e}")

        return IngestResponse(
            success=True,
            message=f"Processed {processed} events" + (f", {failed} duplicates skipped" if failed > 0 else ""),
            events_processed=processed
        )

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Error processing events: {str(e)}",
                "events_processed": 0
            }
        )


@app.get("/events", tags=["Query"])
async def get_events(
    os_type: str = None,
    severity: int = None,
    severity_min: int = None,
    event_type: str = None,
    source_ip: str = None,
    user: str = None,
    source_host: str = None,
    raw_message: str = None,
    start_date: str = None,
    end_date: str = None,
    limit: int = 1000,
    offset: int = 0,
    client_id: str = None,
    site_id: str = None,
    api_key: str = Header(None)
):
    """
    Retrieve events from the database with optional filters and pagination.

    Query Parameters:
    - os_type: Filter by OS type (exact match)
    - severity: Filter by exact severity level
    - severity_min: Filter by minimum severity level (inclusive)
    - event_type: Filter by event type (exact match)
    - source_ip: Filter by source IP (exact match)
    - user: Filter by username (case-insensitive partial match)
    - source_host: Filter by source hostname (exact match)
    - raw_message: Filter by raw message content (case-insensitive)
    - start_date: Filter events on/after this date (ISO format: YYYY-MM-DD)
    - end_date: Filter events on/before this date (ISO format: YYYY-MM-DD)
    - limit: Maximum number of events to return (default 1000, max 10000)
    - offset: Number of events to skip for pagination (default 0)

    Returns:
    {
        "success": true,
        "total_count": 12345,
        "offset": 0,
        "limit": 100,
        "count": 100,
        "events": [...]
    }
    """

    identity = require_identity(api_key)
    scoped = effective_client_id(identity, client_id)
    scoped_site = effective_site_id(identity, site_id)

    try:
        # Limit the maximum number of events that can be returned
        limit = min(limit, 10000)

        # Call the database function with all available filters
        result = get_events_by_filter(
            os_type=os_type,
            severity=severity,
            severity_min=severity_min,
            event_type=event_type,
            source_ip=source_ip,
            user=user,
            source_host=source_host,
            raw_message=raw_message,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
            client_id=scoped,
            site_id=scoped_site,
        )

        events = collapse_docker_runs(result["events"])
        return {
            "success": True,
            "total_count": result['total_count'],
            "offset": result['offset'],
            "limit": result['limit'],
            "count": len(events),
            "events": events,
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Error retrieving events: {str(e)}",
                "total_count": 0,
                "offset": offset,
                "limit": limit,
                "count": 0,
                "events": []
            }
        )


@app.get("/metrics", response_model=dict, tags=["Analytics"])
async def get_metrics(
    client_id: str = None,
    site_id: str = None,
    api_key: str = Header(None),
):
    """
    Get key metrics for the dashboard.
    Includes alerts in last 24h, threats by OS, top attacking IPs, etc.
    """

    identity = require_identity(api_key)
    scoped = effective_client_id(identity, client_id)
    scoped_site = effective_site_id(identity, site_id)

    try:
        metrics = get_metrics_24h(client_id=scoped, site_id=scoped_site)
        top_ips = get_top_attacking_ips(10, client_id=scoped, site_id=scoped_site)
        events_per_min = get_events_per_minute(24, client_id=scoped, site_id=scoped_site)
        
        return {
            "success": True,
            "total_alerts_24h": metrics["total_alerts_24h"],
            "threats_by_os": metrics["threats_by_os"],
            "most_blocked_domain": metrics["most_blocked_domain"],
            "top_attacking_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "events_per_minute": events_per_min
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Error calculating metrics: {str(e)}"
            }
        )


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "api_version": "1.0.0"
    }


def configured_inactive_minutes() -> int:
    """Minutes without a heartbeat before a host is down. Dashboard and Telegram share this."""
    return int(get_config("ALERT_INACTIVE_THRESHOLD", os.getenv("ALERT_INACTIVE_THRESHOLD", "5")))


@app.get("/hosts", tags=["Monitoring"])
async def get_hosts_status(
    inactive_threshold: int | None = None,
    client_id: str = None,
    site_id: str = None,
    api_key: str = Header(None)
):
    """
    Get status of all monitored hosts (active/inactive).

    Args:
        inactive_threshold: Minutes since last heartbeat to consider a host inactive.
            Omitted requests use the saved alert setting (default 5).
    """
    identity = require_identity(api_key)
    scoped = effective_client_id(identity, client_id)
    scoped_site = effective_site_id(identity, site_id)

    if inactive_threshold is None:
        inactive_threshold = configured_inactive_minutes()

    try:
        host_status = get_host_status(
            inactive_threshold_minutes=inactive_threshold,
            client_id=scoped,
            site_id=scoped_site,
        )
        needs_agent = host_status.get("needs_agent") or []
        return {
            "success": True,
            "active_hosts": host_status["active"],
            "inactive_hosts": host_status["inactive"],
            "needs_agent_hosts": needs_agent,
            "threshold_minutes": host_status["threshold_minutes"],
            "total_active": len(host_status["active"]),
            "total_inactive": len(host_status["inactive"]),
            "total_needs_agent": len(needs_agent),
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Error retrieving host status: {str(e)}"
            }
        )


@app.post("/heartbeat", tags=["Monitoring"])
async def receive_heartbeat(
    source_host: str = Header(None, alias="source-host"),
    os_type: str = Header(None, alias="os-type"),
    source_site: str = Header(None, alias="source-site"),
    api_key: str = Header(None)
):
    """
    Record a heartbeat from an agent.
    
    This endpoint updates the last_seen timestamp for a host without creating a database event.
    Used to keep track of active agents without cluttering the event log with heartbeat events.
    
    Args:
        source_host: Hostname of the agent sending the heartbeat (header)
        os_type: OS type of the agent (header)
        api_key: API key for authentication (header)
    """
    identity = require_identity(api_key)
    
    if not source_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing source_host header"
        )
    
    if not os_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing os_type header"
        )
    
    try:
        origin = identity.get("client_id") or DEFAULT_CLIENT_ID
        placed = None
        if identity.get("role") != ROLE_OPERATOR:
            placed = lookup_placement(origin, source_host)
        success = record_heartbeat(
            source_host, os_type,
            client_id=placed["client_id"] if placed else origin,
            site_id=placed["site_id"] if placed else effective_site_id(identity, source_site),
        )
        
        if success:
            return {
                "success": True,
                "message": f"Heartbeat recorded for {source_host}",
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "message": f"Failed to record heartbeat for {source_host}"
                }
            )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Error recording heartbeat: {str(e)}"
            }
        )


@app.get("/alert-config", tags=["Alerts"])
async def get_alert_config(api_key: str = Header(None)):
    """Get current alert configuration."""
    validate_api_key(api_key)

    # Fetch from DB, fallback to env vars
    severity = int(get_config("ALERT_SEVERITY_THRESHOLD", os.getenv("ALERT_SEVERITY_THRESHOLD", "4")))
    inactive = configured_inactive_minutes()
    enable_val = get_config("ENABLE_TELEGRAM_ALERTS", os.getenv("ENABLE_TELEGRAM_ALERTS", "true"))
    quiet = get_config("ALERT_QUIET_HOURS", os.getenv("ALERT_QUIET_HOURS", ""))

    return {
        "success": True,
        "config": {
            "severity_threshold": severity,
            "inactive_threshold_minutes": inactive,
            "check_interval_seconds": int(os.getenv("ALERT_CHECK_INTERVAL", "60")),
            "enable_alerts": str(enable_val).lower() == "true",
            "quiet_hours": quiet,
            "telegram_configured": bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))
        }
    }


@app.post("/alert-config/severity-threshold", tags=["Alerts"])
async def set_severity_threshold(threshold: int, api_key: str = Header(None)):
    """Update alert severity threshold (requires restart to take effect)."""
    validate_api_key(api_key)

    if threshold < 1 or threshold > 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Severity threshold must be between 1 and 5"
        )

    # Persist to database
    set_config("ALERT_SEVERITY_THRESHOLD", str(threshold))

    return {
        "success": True,
        "message": f"Severity threshold updated to {threshold}",
        "note": "Changes applied immediately",
        "env_variable": "ALERT_SEVERITY_THRESHOLD"
    }


@app.post("/alert-config/inactive-threshold", tags=["Alerts"])
async def set_inactive_threshold(minutes: int, api_key: str = Header(None)):
    """Update inactive host threshold (requires restart to take effect)."""
    validate_api_key(api_key)

    if minutes < 1 or minutes > 1440:  # Max 24 hours
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive threshold must be between 1 and 1440 minutes"
        )

    # Persist to database
    set_config("ALERT_INACTIVE_THRESHOLD", str(minutes))

    return {
        "success": True,
        "message": f"Inactive threshold updated to {minutes} minutes",
        "note": "Changes applied immediately",
        "env_variable": "ALERT_INACTIVE_THRESHOLD"
    }


@app.post("/alert-config/quiet-hours", tags=["Alerts"])
async def set_quiet_hours(quiet_hours: str, api_key: str = Header(None)):
    """Set quiet hours to suppress alerts (format: HH:MM-HH:MM or empty to disable)."""
    validate_api_key(api_key)

    if quiet_hours and "-" in quiet_hours:
        try:
            start_str, end_str = quiet_hours.split("-")
            start_hour, start_min = map(int, start_str.split(":"))
            end_hour, end_min = map(int, end_str.split(":"))

            if not (0 <= start_hour < 24 and 0 <= start_min < 60):
                raise ValueError("Invalid start time")
            if not (0 <= end_hour < 24 and 0 <= end_min < 60):
                raise ValueError("Invalid end time")
        except (ValueError, IndexError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid quiet hours format. Use HH:MM-HH:MM (e.g., 22:00-06:00)"
            )
    elif quiet_hours:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid quiet hours format. Use HH:MM-HH:MM (e.g., 22:00-06:00)"
        )

    # Persist to database
    set_config("ALERT_QUIET_HOURS", quiet_hours)

    return {
        "success": True,
        "message": f"Quiet hours updated to: {quiet_hours if quiet_hours else 'disabled'}",
        "note": "Changes applied immediately",
        "env_variable": "ALERT_QUIET_HOURS"
    }


@app.post("/alert-config/enable", tags=["Alerts"])
async def enable_alerts(enabled: bool, api_key: str = Header(None)):
    """Enable or disable alert sending."""
    validate_api_key(api_key)

    # Persist to database
    set_config("ENABLE_TELEGRAM_ALERTS", "true" if enabled else "false")

    return {
        "success": True,
        "message": f"Alerts {'enabled' if enabled else 'disabled'}",
        "note": "Changes applied immediately",
        "env_variable": "ENABLE_TELEGRAM_ALERTS",
        "value": "true" if enabled else "false"
    }


@app.delete("/hosts/{hostname}", tags=["Hosts"])
async def delete_host(hostname: str, client_id: str = None, api_key: str = Header(None)):
    """Remove one monitored endpoint so it leaves the host list.

    client_id limits the delete to that organization. Without it, every
    organization row for this hostname is removed. alert_history is kept.
    """
    validate_api_key(api_key)

    try:
        result = remove_monitored_host(hostname, client_id)
    except Exception as exc:
        print(f"Error removing host {hostname}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove host",
        )
    if not result["removed"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{hostname}' was not found",
        )
    return {
        "success": True,
        "message": f"Removed {hostname}",
        "host": hostname,
        "client_id": client_id,
        "deleted": result,
    }


@app.post("/alerts/telegram/test", tags=["Alerts"])
async def test_telegram_connection(request: Request, api_key: str = Header(None)):
    """Test Telegram bot connection."""
    validate_api_key(api_key)

    body = await request.json()
    bot_token = body.get("bot_token", "")
    chat_id = body.get("chat_id", "")

    if not bot_token or not chat_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing bot_token or chat_id"
        )

    try:
        import urllib.request
        import json as json_lib

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": "Heimdall Security Monitor - Connection Test ✓\n\nTelegram alerts are working properly!"
        }

        # Prepare the request
        json_data = json_lib.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=json_data,
            headers={'Content-Type': 'application/json'}
        )

        # Make the request
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return {
                        "success": True,
                        "message": "Telegram connection test successful"
                    }
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Telegram API error: {error_body}"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to test Telegram connection: {str(e)}"
        )


@app.post("/alerts/telegram/config", tags=["Alerts"])
async def save_telegram_config(request: Request, api_key: str = Header(None)):
    """Save Telegram bot configuration."""
    validate_api_key(api_key)

    body = await request.json()
    bot_token = body.get("bot_token", "")
    chat_id = body.get("chat_id", "")

    if not bot_token or not chat_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing bot_token or chat_id"
        )

    try:
        # Store in environment or file
        with open(".env.telegram", "w") as f:
            f.write(f"TELEGRAM_BOT_TOKEN={bot_token}\n")
            f.write(f"TELEGRAM_CHAT_ID={chat_id}\n")

        return {
            "success": True,
            "message": "Telegram configuration saved successfully",
            "note": "Restart API server for changes to take effect"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save configuration: {str(e)}"
        )


@app.post("/system-status", tags=["Monitoring"])
async def ingest_system_status(request: SystemStatusRequest, api_key: str = Header(None)):
    """Ingest detailed system status from an agent and append metric samples."""
    identity = require_identity(api_key)
    
    try:
        payload = stamp_ingested(request.status.model_dump(), identity)
        record_heartbeat(
            payload["source_host"], payload["os_type"],
            client_id=payload.get("client_id"),
            site_id=payload.get("site_id"),
        )
        
        success = upsert_system_status(payload)
        samples = status_to_samples(
            payload,
            client_id=payload.get("client_id"),
            site_id=payload.get("site_id"),
        )
        if samples:
            insert_metric_samples(samples)

        if success:
            return {"success": True, "message": "System status updated", "samples_stored": len(samples)}
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "message": "Failed to store system status"}
            )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Error: {str(e)}"}
        )

@app.get("/system-status/{hostname}", tags=["Monitoring"])
async def retrieve_system_status(hostname: str, client_id: str = None, api_key: str = Header(None)):
    """Get detailed system status for a specific host."""
    identity = require_identity(api_key)
    scoped = effective_client_id(identity, client_id)
    
    status = get_system_status(hostname, client_id=scoped)
    if status:
        return {"success": True, "status": status}
    else:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Host status not found"}
        )


@app.post("/metrics/samples", tags=["Metrics"])
async def ingest_metric_samples(request: MetricSamplesRequest, api_key: str = Header(None)):
    """Append host metric samples (time-series)."""
    identity = require_identity(api_key)
    samples = [stamp_ingested(s.model_dump(), identity) for s in request.samples]
    stored = insert_metric_samples(samples)
    return {"success": True, "samples_stored": stored}


@app.get("/metrics/query", tags=["Metrics"])
async def metrics_query(
    source_host: str = None,
    metric: str = None,
    start: str = None,
    end: str = None,
    step: int = 0,
    client_id: str = None,
    site_id: str = None,
    api_key: str = Header(None),
):
    """Time-window query over host metrics. `step` is bucket size in seconds."""
    identity = require_identity(api_key)
    scoped = effective_client_id(identity, client_id)
    scoped_site = effective_site_id(identity, site_id)
    points = query_host_metrics(
        source_host=source_host,
        metric=metric,
        client_id=scoped,
        start=start,
        end=end,
        step_seconds=step or 0,
        site_id=scoped_site,
    )
    return {"success": True, "count": len(points), "points": points}


@app.get("/metrics/latest", tags=["Metrics"])
async def metrics_latest(client_id: str = None, site_id: str = None, api_key: str = Header(None)):
    """Latest sample per host+metric for the fleet strip."""
    identity = require_identity(api_key)
    scoped = effective_client_id(identity, client_id)
    scoped_site = effective_site_id(identity, site_id)
    from datetime import datetime, timedelta, timezone
    start = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    rows = query_host_metrics(client_id=scoped, start=start, step_seconds=0, site_id=scoped_site)
    latest = latest_by_host(rows, client_id=scoped)
    snapshots = get_all_system_status(client_id=scoped, site_id=scoped_site)
    return {
        "success": True,
        "latest": list(latest.values()),
        "snapshots": snapshots,
    }


@app.get("/me", tags=["Tenancy"])
async def whoami(api_key: str = Header(None)):
    identity = require_identity(api_key)
    return {"success": True, "identity": identity}


def _org_list_payload(identity: dict) -> dict:
    if identity.get("role") != ROLE_OPERATOR:
        cid = identity.get("client_id")
        client = get_client(cid) if cid else None
        orgs = [client] if client else []
    else:
        orgs = list_clients()
    return {"success": True, "organizations": orgs, "clients": orgs}


@app.get("/clients", tags=["Tenancy"])
async def clients_list(api_key: str = Header(None)):
    identity = require_identity(api_key)
    return _org_list_payload(identity)


@app.get("/orgs", tags=["Tenancy"])
async def orgs_list(api_key: str = Header(None)):
    """Organization workspaces (same records as clients; dedicated UI path later)."""
    identity = require_identity(api_key)
    return _org_list_payload(identity)


@app.post("/clients", tags=["Tenancy"])
async def clients_create(request: ClientCreateRequest, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    import re
    slug = re.sub(r"[^a-z0-9-]+", "-", request.name.lower()).strip("-") or "client"
    from uuid import uuid4
    client_id = f"{slug}-{str(uuid4())[:8]}"
    if not create_client(client_id, request.name, request.telegram_chat_id, request.site_name or "default"):
        raise HTTPException(status_code=500, detail="Failed to create client")
    raw_key = generate_api_key("hk")
    insert_api_key(
        hash_api_key(raw_key),
        key_prefix(raw_key),
        "agent",
        client_id,
        site_id=f"{client_id}-{request.site_name or 'default'}",
        label=f"{request.name} agent",
    )
    site_id = f"{client_id}-{request.site_name or 'default'}"
    return {
        "success": True,
        "client_id": client_id,
        "organization_id": client_id,
        "slug": client_id,
        "name": request.name,
        "site_id": site_id,
        "workspace_path": f"/org/{client_id}",
        "agent_api_key": raw_key,
        "note": "Store this agent API key now; it is not shown again.",
    }


@app.get("/orgs/{client_id}", tags=["Tenancy"])
async def orgs_get(client_id: str, api_key: str = Header(None)):
    return await clients_get(client_id, api_key)


@app.get("/clients/{client_id}", tags=["Tenancy"])
async def clients_get(client_id: str, api_key: str = Header(None)):
    identity = require_identity(api_key)
    if identity.get("role") != ROLE_OPERATOR and identity.get("client_id") != client_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    client = get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"success": True, "client": client}


@app.patch("/clients/{client_id}", tags=["Tenancy"])
async def clients_update(client_id: str, request: ClientUpdateRequest, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    if not get_client(client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    if not update_client(client_id, request.name, request.telegram_chat_id):
        raise HTTPException(status_code=500, detail="Failed to update client")
    return {"success": True, "client": get_client(client_id)}


@app.delete("/clients/{client_id}", tags=["Tenancy"])
async def clients_delete(client_id: str, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    if client_id == "default":
        raise HTTPException(status_code=400, detail="Cannot delete the default client")
    if not delete_client(client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    return {"success": True, "deleted": client_id}


@app.post("/clients/{client_id}/rotate-key", tags=["Tenancy"])
async def clients_rotate_key(client_id: str, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    client = get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    delete_api_keys_for_client(client_id)
    raw_key = generate_api_key("hk")
    sites = client.get("sites") or []
    site_id = sites[0]["id"] if sites else f"{client_id}-default"
    insert_api_key(hash_api_key(raw_key), key_prefix(raw_key), "agent", client_id, site_id, f"{client.get('name')} agent")
    return {
        "success": True,
        "client_id": client_id,
        "agent_api_key": raw_key,
        "note": "Previous agent keys for this client no longer work. Store the new key now.",
    }


@app.post("/clients/{client_id}/sites", tags=["Tenancy"])
async def sites_create(client_id: str, request: SiteCreateRequest, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    if not get_client(client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    import re
    slug = re.sub(r"[^a-z0-9-]+", "-", request.name.lower()).strip("-") or "site"
    site_id = f"{client_id}-{slug}"
    if get_site(site_id):
        raise HTTPException(status_code=409, detail="Site already exists")
    if not create_site(site_id, client_id, request.name):
        raise HTTPException(status_code=500, detail="Failed to create site")
    return {"success": True, "site": {"id": site_id, "client_id": client_id, "name": request.name}}


@app.patch("/sites/{site_id}", tags=["Tenancy"])
async def sites_update(site_id: str, request: SiteUpdateRequest, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    if not get_site(site_id):
        raise HTTPException(status_code=404, detail="Site not found")
    if not update_site(site_id, request.name):
        raise HTTPException(status_code=500, detail="Failed to update site")
    return {"success": True, "site": get_site(site_id)}


@app.post("/endpoints/move", tags=["Tenancy"])
async def endpoints_move(request: EndpointMoveRequest, api_key: str = Header(None)):
    """Move one endpoint, its stored rows, and later ingests to another organization or site."""
    identity = require_identity(api_key)
    require_operator(identity)
    try:
        moved = move_endpoint(
            request.source_host,
            request.client_id,
            request.destination_client_id,
            request.destination_site_id,
        )
    except PlacementError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    return {"success": True, "endpoint": moved}


@app.delete("/sites/{site_id}", tags=["Tenancy"])
async def sites_delete(site_id: str, api_key: str = Header(None)):
    identity = require_identity(api_key)
    require_operator(identity)
    if not delete_site(site_id):
        raise HTTPException(status_code=400, detail="Cannot delete the last site or site not found")
    return {"success": True, "deleted": site_id}


@app.get("/alert-rules", tags=["Alerts"])
async def alert_rules_list(api_key: str = Header(None)):
    require_identity(api_key)
    return {"success": True, "rules": list_alert_rules()}


def _action1_http(exc: Action1Error):
    token_call = "/oauth2/token" in (exc.detail or "")
    if exc.status == 401 or (exc.status == 403 and token_call):
        region = get_config("ACTION1_REGION", "") or ""
        label = REGION_LABELS.get(region) or region or "the selected region"
        raise HTTPException(
            status_code=502,
            detail=(
                f"Action1 refused the credentials for {label}. "
                "A client id works only in the region where it was created."
            ),
        )
    if exc.status == 403:
        raise HTTPException(
            status_code=502,
            detail="Action1 denied the request. The saved role cannot perform it.",
        )
    if exc.status in (400, 404, 429):
        raise HTTPException(status_code=exc.status, detail=exc.detail)
    raise HTTPException(status_code=502, detail=exc.detail or "Action1 could not be reached")


@app.get("/action1", tags=["Action1"])
async def action1_get(client_id: str = None, api_key: str = Header(None)):
    """Connection status, links, and the last Action1 sync. The secret is never returned."""
    validate_api_key(api_key)
    return action1_state(client_id)


@app.post("/action1/config", tags=["Action1"])
async def action1_config_save(request: Request, api_key: str = Header(None)):
    """Store the Action1 region and API credentials. A blank secret keeps the saved one."""
    validate_api_key(api_key)
    body = await request.json()
    try:
        settings = save_settings(
            body.get("region"),
            body.get("client_id"),
            body.get("client_secret"),
            bool(body.get("page_critical")),
        )
    except Action1Error as exc:
        _action1_http(exc)
    return {"success": True, "settings": settings}


@app.post("/action1/test", tags=["Action1"])
def action1_test(api_key: str = Header(None)):
    """Exchange credentials and list Action1 organizations. The token is not returned."""
    validate_api_key(api_key)
    try:
        organizations = refresh_organizations()
    except Action1Error as exc:
        _action1_http(exc)
    return {"success": True, "organizations": organizations}


@app.post("/action1/links", tags=["Action1"])
async def action1_link(request: Request, api_key: str = Header(None)):
    """Map one Action1 organization onto a Heimdall organization."""
    validate_api_key(api_key)
    body = await request.json()
    try:
        link = link_organization(
            body.get("action1_org_id"),
            body.get("action1_org_name") or "",
            body.get("client_id"),
        )
    except Action1Error as exc:
        _action1_http(exc)
    return {"success": True, "link": link}


@app.delete("/action1/links/{action1_org_id}", tags=["Action1"])
async def action1_unlink(action1_org_id: str, api_key: str = Header(None)):
    """Stop syncing an Action1 organization. Stored events stay. Nothing is deleted in Action1."""
    validate_api_key(api_key)
    if not unlink_organization(action1_org_id):
        raise HTTPException(status_code=404, detail="Action1 organization link was not found")
    return {"success": True, "action1_org_id": action1_org_id}


@app.post("/action1/sync", tags=["Action1"])
def action1_sync(api_key: str = Header(None)):
    """Read linked Action1 organizations into inventory and SIEM events."""
    validate_api_key(api_key)
    try:
        summary = sync_action1()
    except Action1Error as exc:
        _action1_http(exc)
    return {"success": True, "summary": summary}


@app.delete("/action1/endpoints/{action1_org_id}/{endpoint_id}", tags=["Action1"])
def action1_endpoint_delete(action1_org_id: str, endpoint_id: str, api_key: str = Header(None)):
    """Delete one decommissioned endpoint in Action1, then drop the local inventory row."""
    validate_api_key(api_key)
    try:
        removed = remove_remote_endpoint(action1_org_id, endpoint_id)
    except Action1Error as exc:
        _action1_http(exc)
    return {"success": True, "removed": removed}


@app.post("/action1/deploy", tags=["Action1"])
def action1_deploy(body: AgentDeployRequest, request: Request, api_key: str = Header(None)):
    """Run the Heimdall installer once on selected Windows, Mac, and Linux endpoints."""
    validate_api_key(api_key)
    try:
        result = deploy_agents(
            body.endpoints,
            hub_url=body.hub_url,
            hostname=body.hostname,
            role=body.role,
            fallback_url=str(request.base_url or ""),
        )
    except Action1Error as exc:
        if exc.status == 403 and "permission to run automations" in (exc.detail or ""):
            raise HTTPException(status_code=502, detail=exc.detail)
        _action1_http(exc)
    return {"success": True, **result}


@app.get("/docker-servers", tags=["Docker"])
async def docker_servers_list(client_id: str = None, site_id: str = None, api_key: str = Header(None)):
    """Docker servers in the selected organization. The SSH private key is not included."""
    identity = validate_api_key(api_key)
    from .docker_collect import ensure_collector_key
    from .docker_store import list_docker_servers
    scoped = effective_client_id(identity, client_id)
    site = effective_site_id(identity, site_id) if scoped else None
    try:
        public_key = ensure_collector_key()
    except Exception:
        public_key = ""
    return {
        "servers": list_docker_servers(scoped, site),
        "public_key": public_key,
    }


@app.post("/docker-servers", tags=["Docker"])
async def docker_servers_create(request: Request, api_key: str = Header(None)):
    """Add a docker server to an organization. Collection uses the hub SSH key."""
    identity = validate_api_key(api_key)
    from .docker_logs import DockerLogError
    from .docker_store import create_docker_server
    body = await request.json()
    client_id = effective_client_id(identity, body.get("client_id"))
    if not client_id:
        raise HTTPException(status_code=400, detail="Choose an organization for this docker server.")
    site_id = (body.get("site_id") or "").strip()
    if not site_belongs_to_client(site_id, client_id):
        raise HTTPException(status_code=400, detail="Pick a site that belongs to this organization.")
    try:
        server = create_docker_server(
            client_id,
            site_id,
            body.get("name") or "",
            body.get("ssh_host") or "",
            body.get("ssh_user") or "",
            body.get("log_dir") or "",
            body.get("ssh_port") or 22,
        )
    except DockerLogError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"success": True, "server": server}


@app.delete("/docker-servers/{server_id}", tags=["Docker"])
async def docker_servers_delete(server_id: str, client_id: str = None, api_key: str = Header(None)):
    """Stop collecting a docker server. Events already stored stay."""
    identity = validate_api_key(api_key)
    from .docker_store import delete_docker_server
    scoped = effective_client_id(identity, client_id)
    if not delete_docker_server(server_id, scoped):
        raise HTTPException(status_code=404, detail="Docker server was not found in this organization.")
    return {"success": True, "id": server_id}


@app.post("/docker-servers/{server_id}/poll", tags=["Docker"])
def docker_servers_poll(server_id: str, client_id: str = None, api_key: str = Header(None)):
    """Read the server's docker-update logs once."""
    identity = validate_api_key(api_key)
    from .docker_collect import poll_server
    from .docker_store import get_docker_server
    scoped = effective_client_id(identity, client_id)
    server = get_docker_server(server_id, scoped)
    if server is None:
        raise HTTPException(status_code=404, detail="Docker server was not found in this organization.")
    result = poll_server(server)
    return {"success": result["success"], "result": result, "server": get_docker_server(server_id, scoped)}


if __name__ == "__main__":
    import uvicorn
    server_host = os.getenv("SIEM_SERVER_HOST", "0.0.0.0")
    server_port = int(os.getenv("SIEM_SERVER_PORT", "8010"))
    uvicorn.run(app, host=server_host, port=server_port)

