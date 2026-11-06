"""
Host metric time-series helpers.

Converts a SystemStatus snapshot into append-only samples and provides
window filtering plus step bucketing used by GET /metrics/query.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Iterable, Optional


METRIC_CPU = "cpu_usage"
METRIC_MEMORY = "memory_percent"
METRIC_DISK = "disk_percent"
METRIC_NET_SENT = "net_bytes_sent"
METRIC_NET_RECV = "net_bytes_recv"

DEFAULT_CLIENT_ID = "default"
DEFAULT_SITE_ID = "default"

# Snap/loop images, overlays, and ram disks always look "full" and are not
# customer storage. Alerting on them is a false positive (e.g. /snap/core24/…).
IGNORED_FS_TYPES = frozenset({
    "squashfs", "overlay", "overlay2", "tmpfs", "devtmpfs", "ramfs",
    "proc", "sysfs", "cgroup", "cgroup2", "nsfs", "autofs", "iso9660",
    "udf", "devpts", "fuse.lxcfs", "fuse.portal",
})
IGNORED_MOUNT_PREFIXES = (
    "/snap",
    "/var/lib/snapd",
    "/var/lib/docker",
    "/var/lib/containers",
    "/run",
    "/sys",
    "/proc",
    "/dev",
)


def is_real_disk(disk: dict) -> bool:
    """True when this mount is real capacity we should chart and alert on."""
    if not isinstance(disk, dict):
        return False
    mount = str(disk.get("mount") or disk.get("mountpoint") or "")
    if not mount or mount == "?":
        return False
    fstype = str(disk.get("fstype") or disk.get("fs") or "").lower()
    device = str(disk.get("device") or "")
    if fstype in IGNORED_FS_TYPES:
        return False
    if device.startswith("/dev/loop"):
        return False
    lowered = mount.lower()
    if "/snap/" in lowered or lowered == "/snap" or lowered.startswith("/snap/"):
        return False
    for prefix in IGNORED_MOUNT_PREFIXES:
        if mount == prefix or mount.startswith(prefix + "/"):
            return False
    return True


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601 / datetime into an aware UTC datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if value is None:
        return datetime.now(timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def isoformat_z(dt: datetime) -> str:
    return parse_timestamp(dt).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_to_samples(status: dict, client_id: str = None, site_id: str = None) -> list[dict]:
    """
    Turn a SystemStatus snapshot into append-only metric samples.

    Metric names are stable so Linux, Windows (Python/EXE), macOS, and the
    PowerShell agent all write the same series.
    """
    if not status:
        return []

    host = status.get("source_host") or "unknown"
    ts = status.get("timestamp") or datetime.now(timezone.utc).isoformat()
    cid = client_id or status.get("client_id") or DEFAULT_CLIENT_ID
    sid = site_id or status.get("site_id") or DEFAULT_SITE_ID
    samples: list[dict] = []

    cpu = status.get("cpu_usage")
    if cpu is not None:
        samples.append(_sample(ts, host, cid, sid, METRIC_CPU, float(cpu), {}))

    mem = status.get("memory_percent")
    if mem is not None:
        samples.append(_sample(ts, host, cid, sid, METRIC_MEMORY, float(mem), {}))

    for disk in status.get("disk_info") or []:
        if not isinstance(disk, dict):
            continue
        if not is_real_disk(disk):
            continue
        pct = disk.get("percent")
        if pct is None:
            continue
        mount = str(disk.get("mount") or disk.get("mountpoint") or "?")
        samples.append(
            _sample(ts, host, cid, sid, METRIC_DISK, float(pct), {"mount": mount})
        )

    net = status.get("net_io") or {}
    if isinstance(net, dict):
        if net.get("bytes_sent") is not None:
            samples.append(
                _sample(ts, host, cid, sid, METRIC_NET_SENT, float(net["bytes_sent"]), {})
            )
        if net.get("bytes_recv") is not None:
            samples.append(
                _sample(ts, host, cid, sid, METRIC_NET_RECV, float(net["bytes_recv"]), {})
            )

    return samples


def _sample(ts, host, client_id, site_id, metric, value, labels) -> dict:
    return {
        "time": ts if isinstance(ts, str) else isoformat_z(ts),
        "source_host": host,
        "client_id": client_id,
        "site_id": site_id,
        "metric": metric,
        "value": float(value),
        "labels": labels or {},
    }


def _labels_key(labels: Any) -> str:
    if not labels:
        return ""
    if not isinstance(labels, dict):
        return str(labels)
    return ",".join(f"{k}={labels[k]}" for k in sorted(labels))


def query_samples(
    rows: Iterable[dict],
    *,
    source_host: Optional[str] = None,
    metric: Optional[str] = None,
    client_id: Optional[str] = None,
    start: Optional[Any] = None,
    end: Optional[Any] = None,
    step_seconds: int = 0,
) -> list[dict]:
    """
    Filter metric rows by host/metric/client/window and optionally downsample.

    `step_seconds <= 1` keeps native samples. Larger steps average values
    per (host, metric, labels, bucket).
    """
    start_dt = parse_timestamp(start) if start else None
    end_dt = parse_timestamp(end) if end else None
    filtered: list[dict] = []

    for row in rows:
        if source_host and row.get("source_host") != source_host:
            continue
        if metric and row.get("metric") != metric:
            continue
        if client_id and row.get("client_id") not in (None, client_id):
            continue
        try:
            ts = parse_timestamp(row.get("time") or row.get("timestamp"))
        except (TypeError, ValueError):
            continue
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts > end_dt:
            continue
        item = dict(row)
        item["_ts"] = ts
        filtered.append(item)

    filtered.sort(key=lambda r: r["_ts"])
    if step_seconds and step_seconds > 1:
        filtered = _bucket(filtered, step_seconds)

    out = []
    for row in filtered:
        ts = row["_ts"]
        out.append({
            "time": isoformat_z(ts),
            "source_host": row.get("source_host"),
            "client_id": row.get("client_id") or DEFAULT_CLIENT_ID,
            "site_id": row.get("site_id") or DEFAULT_SITE_ID,
            "metric": row.get("metric"),
            "value": float(row.get("value") or 0),
            "labels": row.get("labels") or {},
        })
    return out


def _bucket(rows: list[dict], step_seconds: int) -> list[dict]:
    buckets: dict[tuple, dict] = {}
    epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)
    step = timedelta(seconds=step_seconds)

    for row in rows:
        ts: datetime = row["_ts"]
        delta = ts - epoch
        bucket_index = int(delta.total_seconds() // step_seconds)
        bucket_time = epoch + step * bucket_index
        key = (
            row.get("source_host"),
            row.get("metric"),
            _labels_key(row.get("labels")),
            bucket_time,
        )
        acc = buckets.get(key)
        if acc is None:
            buckets[key] = {
                **row,
                "_ts": bucket_time,
                "_sum": float(row.get("value") or 0),
                "_n": 1,
            }
        else:
            acc["_sum"] += float(row.get("value") or 0)
            acc["_n"] += 1

    result = []
    for acc in buckets.values():
        acc["value"] = acc["_sum"] / acc["_n"]
        result.append(acc)
    result.sort(key=lambda r: (r["_ts"], r.get("source_host") or "", r.get("metric") or ""))
    return result


def latest_by_host(rows: Iterable[dict], client_id: Optional[str] = None) -> dict[str, dict]:
    """Return the newest sample per host+metric+labels (for fleet strips)."""
    latest: dict[str, dict] = {}
    for row in query_samples(rows, client_id=client_id, step_seconds=0):
        key = f"{row['source_host']}|{row['metric']}|{_labels_key(row.get('labels'))}"
        prev = latest.get(key)
        if prev is None or row["time"] >= prev["time"]:
            latest[key] = row
    return latest
