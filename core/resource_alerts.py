"""
Templated resource-threshold alerts evaluated against host metric series.

Defaults match the consulting alignment plan: CPU/memory 90% for 10 minutes,
disk 90% on any mount. SIEM severity and host-down alerts stay separate.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from .host_metrics import (
    METRIC_CPU,
    METRIC_DISK,
    METRIC_MEMORY,
    _labels_key,
    is_real_disk,
    parse_timestamp,
)


DEFAULT_RULES = [
    {
        "id": "cpu_high",
        "name": "CPU high",
        "metric": METRIC_CPU,
        "op": ">",
        "threshold": 90.0,
        "duration_seconds": 600,
        "severity": 4,
        "hysteresis": 5.0,
        "enabled": True,
    },
    {
        "id": "memory_high",
        "name": "Memory high",
        "metric": METRIC_MEMORY,
        "op": ">",
        "threshold": 90.0,
        "duration_seconds": 600,
        "severity": 4,
        "hysteresis": 5.0,
        "enabled": True,
    },
    {
        "id": "disk_high",
        "name": "Disk high",
        "metric": METRIC_DISK,
        "op": ">",
        "threshold": 90.0,
        "duration_seconds": 600,
        "severity": 4,
        "hysteresis": 5.0,
        "enabled": True,
    },
]


def compare(value: float, op: str, threshold: float) -> bool:
    if op in (">", "gt"):
        return value > threshold
    if op in (">=", "gte"):
        return value >= threshold
    if op in ("<", "lt"):
        return value < threshold
    if op in ("<=", "lte"):
        return value <= threshold
    if op in ("==", "=", "eq"):
        return value == threshold
    raise ValueError(f"unsupported op: {op}")


def sustained_breach(
    points: Iterable[dict],
    rule: dict,
    now: Optional[datetime] = None,
) -> bool:
    """
    True when every sample in the last `duration_seconds` breaches the
    threshold AND the window is actually covered (oldest sample is at
    or before now - duration). Empty/short windows do not fire.
    """
    now = now or datetime.now(timezone.utc)
    duration = int(rule.get("duration_seconds") or 0)
    threshold = float(rule["threshold"])
    op = rule.get("op") or ">"
    window_start = now - timedelta(seconds=duration)

    series = []
    for p in points:
        try:
            ts = parse_timestamp(p.get("time") or p.get("timestamp"))
            val = float(p.get("value"))
        except (TypeError, ValueError):
            continue
        if ts > now:
            continue
        if ts >= window_start:
            series.append((ts, val))

    if duration <= 0:
        if not series:
            return False
        return compare(series[-1][1], op, threshold)

    if not series:
        return False

    oldest = min(t for t, _ in series)
    # Require the series to reach back to the start of the duration window
    # (30s collector: allow one step of slack).
    slack = timedelta(seconds=max(30, duration * 0.1))
    if oldest > window_start + slack:
        return False

    return all(compare(val, op, threshold) for _, val in series)


def is_cleared(points: Iterable[dict], rule: dict, now: Optional[datetime] = None) -> bool:
    """True when the latest point is at least `hysteresis` below the fire threshold."""
    now = now or datetime.now(timezone.utc)
    series = []
    for p in points:
        try:
            series.append((parse_timestamp(p.get("time") or p.get("timestamp")), float(p.get("value"))))
        except (TypeError, ValueError):
            continue
    if not series:
        return True
    series.sort(key=lambda x: x[0])
    latest = series[-1][1]
    threshold = float(rule["threshold"])
    hysteresis = float(rule.get("hysteresis") or 0)
    op = rule.get("op") or ">"
    clear_at = threshold - hysteresis if op in (">", ">=", "gt", "gte") else threshold + hysteresis
    if op in (">", ">=", "gt", "gte"):
        return latest <= clear_at
    if op in ("<", "<=", "lt", "lte"):
        return latest >= clear_at
    return not compare(latest, op, threshold)


def alert_event_id(rule: dict, source_host: str, labels: Optional[dict] = None) -> str:
    extra = _labels_key(labels or {})
    suffix = f":{extra}" if extra else ""
    return f"resource-{rule.get('id') or rule.get('name')}-{source_host}{suffix}"


def group_series(rows: Iterable[dict]) -> dict[tuple, list[dict]]:
    """Group samples by (host, metric, labels-key)."""
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (
            row.get("source_host"),
            row.get("metric"),
            _labels_key(row.get("labels")),
            tuple(sorted((row.get("labels") or {}).items())),
        )
        groups.setdefault(key, []).append(row)
    return groups


def evaluate_rules(
    rows: Iterable[dict],
    rules: Optional[list[dict]] = None,
    now: Optional[datetime] = None,
) -> list[dict]:
    """
    Return firing alerts: {event_id, rule, source_host, metric, labels, value, severity}.
    """
    rules = [r for r in (rules or DEFAULT_RULES) if r.get("enabled", True)]
    now = now or datetime.now(timezone.utc)
    grouped = group_series(rows)
    firings = []

    for (host, metric, _lk, label_items), points in grouped.items():
        labels = dict(label_items)
        if metric == METRIC_DISK and not is_real_disk({"mount": labels.get("mount")}):
            continue
        for rule in rules:
            if rule.get("metric") != metric:
                continue
            if sustained_breach(points, rule, now=now):
                latest = sorted(points, key=lambda p: parse_timestamp(p.get("time")))[-1]
                firings.append({
                    "event_id": alert_event_id(rule, host, labels),
                    "rule_id": rule.get("id"),
                    "name": rule.get("name"),
                    "source_host": host,
                    "metric": metric,
                    "labels": labels,
                    "value": float(latest.get("value") or 0),
                    "threshold": float(rule["threshold"]),
                    "severity": int(rule.get("severity") or 4),
                    "client_id": latest.get("client_id"),
                })
    return firings
