"""Pull docker-update logs over SSH and store them as Heimdall events.

A matching real agent is a heartbeat. These files are not. os_type DOCKER
is excluded from host status so a quiet log does not page host-down.
The first read of a file is history. Later lines in the live file can page.
Rotated .1 copies stay history. .cache is never requested.
"""

import os
import subprocess
import threading
import time

from .database_pg import insert_events_batch
from .docker_logs import LIVE_NAMES, LOG_NAMES, MAX_READ, reader_script
from .docker_store import get_cursors, list_docker_servers, mark_poll, save_cursor
from .docker_logs import parse_chunk

_poll_lock = threading.Lock()
_thread = None
_KEY_COMMENT = "heimdall-docker-logs"


def key_path() -> str:
    return os.environ.get("SIEM_DOCKER_KEY", "/app/data/docker_collector_ed25519")


def known_hosts_path() -> str:
    override = os.environ.get("SIEM_DOCKER_KNOWN_HOSTS", "")
    if override:
        return override
    return os.path.join(os.path.dirname(key_path()), "docker_known_hosts")


def ensure_collector_key() -> str:
    """Create the hub SSH key once. The private key stays on the server."""
    path = key_path()
    public = path + ".pub"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not os.path.exists(public):
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", path, "-N", "", "-C", _KEY_COMMENT],
            check=True,
            capture_output=True,
        )
    os.chmod(path, 0o600)
    with open(public, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def _ssh(server: dict, remote: list, stdin: bytes = None):
    argv = [
        "ssh",
        "-i", key_path(),
        "-p", str(server["ssh_port"]),
        "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=" + known_hosts_path(),
        "-o", "ConnectTimeout=8",
        "-o", "IdentitiesOnly=yes",
        f"{server['ssh_user']}@{server['ssh_host']}",
        *remote,
    ]
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        timeout=25,
        check=False,
    )


def ssh_run(server: dict, action: str, name: str = None, offset: int = 0, limit: int = MAX_READ):
    """Run list or read. Fall back to sending the reader when it is not installed."""
    args = [action, server["log_dir"]]
    if action == "read":
        args.extend([name, str(offset), str(limit)])
    first = _ssh(server, ["heimdall-docker-logs", *args])
    missing = first.returncode == 127 or (
        b"heimdall-docker-logs" in (first.stderr or b"") and b"not found" in (first.stderr or b"")
    )
    if not missing:
        return first.returncode, first.stdout or b"", first.stderr or b""
    second = _ssh(server, ["sh", "-s", "--", *args], stdin=reader_script().encode())
    return second.returncode, second.stdout or b"", second.stderr or b""


def _parse_list(stdout: bytes) -> dict:
    found = {}
    for line in stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] != "FILE":
            continue
        name = parts[1]
        if parts[2] == "MISSING":
            found[name] = None
            continue
        if len(parts) >= 6 and parts[2] == "SIZE" and parts[4] == "INODE":
            found[name] = {"size": int(parts[3]), "inode": parts[5]}
    return found


def _parse_read(stdout: bytes):
    if stdout.startswith(b"MISSING"):
        return None
    newline = stdout.find(b"\n")
    if newline < 0:
        raise RuntimeError("Docker log reader returned no header")
    header = stdout[:newline].decode("utf-8", "replace").split()
    if len(header) < 4 or header[0] != "SIZE" or header[2] != "INODE":
        raise RuntimeError("Docker log reader returned an unexpected header")
    return {"size": int(header[1]), "inode": header[3], "body": stdout[newline + 1:]}


def _source_ip(host: str) -> str:
    if host and all(part.isdigit() and 0 <= int(part) <= 255 for part in host.split(".")) and host.count(".") == 3:
        return host
    return "N/A"


def _consume_file(server: dict, name: str, cursor: dict, runner) -> tuple:
    """Read new bytes. Returns (events, cursor_update)."""
    offset = int(cursor.get("offset") or 0)
    inode = cursor.get("inode") or ""
    pending = cursor.get("pending") or ""
    bootstrapped = bool(cursor.get("bootstrapped"))
    catchup = name.endswith(".1") or not bootstrapped
    events = []
    for _ in range(12):
        code, stdout, stderr = runner(server, "read", name, offset, MAX_READ)
        if code != 0:
            detail = (stderr or b"").decode("utf-8", "replace").strip()
            raise RuntimeError(detail or f"Reading {name} failed ({code})")
        parsed = _parse_read(stdout)
        if parsed is None:
            return events, {
                "inode": "",
                "offset": 0,
                "pending": "",
                "bootstrapped": bootstrapped,
            }
        if inode and parsed["inode"] != inode:
            offset = 0
            pending = ""
            catchup = name.endswith(".1") or not bootstrapped
            inode = parsed["inode"]
            continue
        inode = parsed["inode"]
        if offset > parsed["size"]:
            offset = 0
            pending = ""
            continue
        body = parsed["body"]
        if not body:
            if offset >= parsed["size"]:
                bootstrapped = True
            break
        text = pending + body.decode("utf-8", "replace")
        if text.endswith("\n") or not text:
            complete, pending = text, ""
        elif "\n" in text:
            complete, pending = text.rsplit("\n", 1)
            complete += "\n"
        else:
            complete, pending = "", text
        if complete:
            events.extend(parse_chunk(
                complete,
                server_id=server["id"],
                source_host=server["name"],
                source_ip=_source_ip(server["ssh_host"]),
                user=server["ssh_user"],
                client_id=server["client_id"],
                site_id=server["site_id"],
                basename=name,
                catchup=catchup,
            ))
        offset += len(body)
        if offset >= parsed["size"] or not body:
            if offset >= parsed["size"]:
                bootstrapped = True
            break
    return events, {
        "inode": inode,
        "offset": offset,
        "pending": pending,
        "bootstrapped": bootstrapped,
    }


def poll_server(server: dict, runner=None) -> dict:
    """Read one server's four log paths and insert new events."""
    runner = runner or ssh_run
    with _poll_lock:
        try:
            code, stdout, stderr = runner(server, "list")
            if code != 0:
                detail = (stderr or stdout or b"").decode("utf-8", "replace").strip()
                raise RuntimeError(detail or f"SSH list failed ({code})")
            listed = _parse_list(stdout if isinstance(stdout, bytes) else stdout.encode())
            if len(listed) < 4:
                raise RuntimeError("The log reader did not report the four docker-update files.")
            cursors = get_cursors(server["id"])
            # Files already on disk at the first collection are history.
            # A log that appears on a later poll, such as the first update.log,
            # is live and can page.
            watched = any(item.get("bootstrapped") for item in cursors.values())
            inserted = 0
            skipped = 0
            for name in LOG_NAMES:
                info = listed.get(name)
                if info is None:
                    continue
                state = cursors.get(name, {})
                if name in LIVE_NAMES and not state and watched:
                    state = {"inode": "", "offset": 0, "pending": "", "bootstrapped": True}
                events, update = _consume_file(server, name, state, runner)
                if events:
                    added, duplicate = insert_events_batch(events)
                    inserted += added
                    skipped += duplicate
                save_cursor(
                    server["id"], name, update["inode"], update["offset"],
                    update["pending"], update["bootstrapped"],
                )
            mark_poll(server["id"], ok=True)
            return {"success": True, "inserted": inserted, "skipped": skipped, "error": None}
        except Exception as exc:
            message = str(exc).strip() or "Collection failed"
            mark_poll(server["id"], error=message, ok=False)
            return {"success": False, "inserted": 0, "skipped": 0, "error": message[:500]}


def poll_all():
    for server in list_docker_servers():
        if not server.get("enabled", True):
            continue
        try:
            poll_server(server)
        except Exception as exc:
            print(f"Docker log poll failed for {server.get('name')}: {exc}")


def _loop():
    interval = int(os.environ.get("SIEM_DOCKER_POLL_SECONDS", "60"))
    if interval < 15:
        interval = 15
    time.sleep(10)
    while True:
        try:
            ensure_collector_key()
            poll_all()
        except Exception as exc:
            print(f"Docker log collector: {exc}")
        time.sleep(interval)


def start_docker_collector():
    """Tail configured docker servers until the process exits."""
    global _thread
    if os.environ.get("SIEM_DOCKER_POLL", "1").lower() in ("0", "false", "no"):
        return None
    if _thread is not None and _thread.is_alive():
        return _thread
    _thread = threading.Thread(target=_loop, name="docker-logs", daemon=True)
    _thread.start()
    return _thread
