"""Settings shared by every Heimdall agent.

Copied next to the agent script by the installer. The hub, the installer,
and the agent all use the same variable names.
"""

import os
import socket
from dataclasses import dataclass

DEFAULT_API_URL = "http://localhost:8010"
INSECURE_API_KEY = "default-insecure-key-change-me"

_INTERVAL_ENV_VARS = (
    "SIEM_INTERVAL",
    "SIEM_LINUX_INTERVAL",
    "SIEM_AGENT_INTERVAL",
    "SIEM_WINDOWS_INTERVAL",
    "SIEM_PIHOLE_INTERVAL",
)


@dataclass
class AgentSettings:
    api_url: str
    api_key: str
    hostname: str
    interval: int
    role: str


def agent_hostname() -> str:
    """Hostname the hub should show for this machine."""
    configured = os.getenv("SIEM_HOSTNAME", "").strip() or os.getenv("HEIMDALL_HOSTNAME", "").strip()
    if configured:
        return configured
    return socket.gethostname()


def load_settings(default_interval: int = 30, default_role: str = "linux") -> AgentSettings:
    """Read SIEM_* environment variables once at startup."""
    api_url = os.getenv("SIEM_API_URL", DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        api_url = DEFAULT_API_URL

    api_key = os.getenv("SIEM_API_KEY", INSECURE_API_KEY).strip() or INSECURE_API_KEY

    interval = default_interval
    for name in _INTERVAL_ENV_VARS:
        raw = os.getenv(name, "").strip()
        if not raw:
            continue
        try:
            interval = int(raw)
        except ValueError:
            interval = default_interval
        break
    if interval < 5:
        interval = 5

    role = os.getenv("SIEM_ROLE", default_role).strip() or default_role
    return AgentSettings(
        api_url=api_url,
        api_key=api_key,
        hostname=agent_hostname(),
        interval=interval,
        role=role,
    )


def state_path(name: str, fallback: str) -> str:
    """State file under SIEM_STATE_DIR, or the old working-directory path."""
    directory = os.getenv("SIEM_STATE_DIR", "").strip()
    if not directory:
        return fallback
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, name)
