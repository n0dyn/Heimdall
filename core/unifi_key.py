"""
Create the agent key the syslog collector uses to POST /ingest.

The raw key is stored in the data volume, not in Telegram config and not in logs.
The hash goes in api_keys so the collector is an agent scoped to site default-unifi.
"""

import os
from pathlib import Path

from .database_pg import create_site, get_site, insert_api_key, lookup_api_key
from .tenancy import generate_api_key, hash_api_key, key_prefix


def key_file_path() -> Path:
    explicit = os.getenv("UNIFI_AGENT_KEY_FILE")
    if explicit:
        return Path(explicit)
    data = os.getenv("HEIMDALL_DATA_DIR")
    if data:
        return Path(data) / "unifi_agent.key"
    if Path("/app").is_dir():
        return Path("/app/data/unifi_agent.key")
    return Path("data/unifi_agent.key")


def ensure_unifi_agent_key() -> str:
    """Return the collector key, creating the site and key row if needed."""
    site_id = "default-unifi"
    if not get_site(site_id):
        create_site(site_id, "default", "unifi")

    path = key_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    env_key = os.getenv("UNIFI_AGENT_KEY", "").strip()
    if env_key:
        raw = env_key
        path.write_text(raw + "\n")
    elif path.exists():
        raw = path.read_text().strip()
    else:
        raw = generate_api_key("hk")
        path.write_text(raw + "\n")

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    if raw and not lookup_api_key(hash_api_key(raw)):
        insert_api_key(
            hash_api_key(raw),
            key_prefix(raw),
            "agent",
            "default",
            site_id,
            "unifi-syslog",
        )
    return raw
