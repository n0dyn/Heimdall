"""
UDP syslog collector for UniFi and other devices that speak syslog.

Listens on SYSLOG_UDP_PORT (default 5514) and POSTs normalized events to the
local API with the UniFi agent key. It does not import or call Telegram.
"""

import os
import socket
import time

import requests

from .unifi_parse import UnifiNormalizer


def _api_base() -> str:
    return os.getenv(
        "HEIMDALL_INTERNAL_API",
        f"http://127.0.0.1:{os.getenv('SIEM_SERVER_PORT', '8010')}",
    ).rstrip("/")


def _load_key() -> str:
    env_key = os.getenv("UNIFI_AGENT_KEY", "").strip()
    if env_key:
        return env_key
    path = os.getenv("UNIFI_AGENT_KEY_FILE", "/app/data/unifi_agent.key")
    if os.path.exists(path):
        with open(path, "r") as handle:
            return handle.read().strip()
    return ""


def _post(api: str, key: str, events: list) -> bool:
    try:
        response = requests.post(
            f"{api}/ingest",
            json={"events": events},
            headers={"api-key": key},
            timeout=30,
        )
        if response.status_code == 200:
            return True
        print(f"Syslog ingest failed: {response.status_code} {response.text[:200]}")
        return False
    except Exception as exc:
        print(f"Syslog ingest error: {exc}")
        return False


def serve() -> None:
    port = int(os.getenv("SYSLOG_UDP_PORT", "5514"))
    api = _api_base()
    normalizer = UnifiNormalizer(
        ingest_clients=os.getenv("UNIFI_INGEST_CLIENTS", "").lower() in ("1", "true", "yes"),
        store_unknown=os.getenv("SYSLOG_STORE_UNKNOWN", "").lower() in ("1", "true", "yes"),
    )

    key = ""
    while not key:
        key = _load_key()
        if key:
            break
        print("Syslog collector waiting for agent key")
        time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(2.0)
    print(f"Syslog collector listening on udp/{port}, forwarding to {api}")

    batch = []
    last_flush = time.time()
    while True:
        try:
            data, _addr = sock.recvfrom(65535)
        except socket.timeout:
            data = b""
        except Exception as exc:
            print(f"Syslog recv error: {exc}")
            time.sleep(1)
            continue

        if data:
            line = data.decode("utf-8", errors="replace").strip("\x00").strip()
            event = normalizer.normalize(line)
            if event:
                batch.append(event)

        now = time.time()
        if batch and (len(batch) >= 50 or now - last_flush >= 2):
            if _post(api, key, batch[:50]):
                del batch[:50]
            elif len(batch) > 500:
                del batch[: len(batch) - 500]
            last_flush = now


def main() -> None:
    if os.getenv("SYSLOG_ENABLED", "true").lower() in ("0", "false", "no"):
        print("Syslog collector disabled")
        return
    serve()


if __name__ == "__main__":
    main()
