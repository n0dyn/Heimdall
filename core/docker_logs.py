"""Parse docker-update logs and reject anything under .cache.

The remote scripts write two append-only files and rotate each one to a
single .1 copy after 2 MB. Fresh CVE and GHSA lines are the findings.
The cache directory is lock files and scratch, and it is not a log.
"""

import os
import re
import uuid
from datetime import datetime, timedelta, timezone

LOG_NAMES = (
    "cve-check.log",
    "cve-check.log.1",
    "update.log",
    "update.log.1",
)
LIVE_NAMES = ("cve-check.log", "update.log")
MAX_READ = 262144
EVENT_NAMESPACE = uuid.UUID("c3d4e5f6-a7b8-4901-8c2d-3e4f5a6b7c8d")

_TS = re.compile(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\]\s?(.*)$")
_FRESH = re.compile(r"^fresh\s+((?:CVE|GHSA)-[A-Za-z0-9][A-Za-z0-9-]*)\s*$")
_SUMMARY = re.compile(
    r"^fixable high/critical:\s*(\d+),\s*new since baseline:\s*(\d+)\s*$"
)
_DONE = re.compile(r"^===== done failures=(\d+) =====$")
_UPDATER_EXIT = re.compile(r"^updater exited\s+(-?\d+)")
_DIR = re.compile(r"^/[A-Za-z0-9_./-]{1,240}$")
_HOST = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")
_USER = re.compile(r"^[a-zA-Z0-9_][A-Za-z0-9_.-]{0,31}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class DockerLogError(ValueError):
    """The operator's docker-server fields cannot be used."""


def validate_log_dir(path: str) -> str:
    """Accept an absolute log directory. Refuse .cache and parent escapes."""
    text = (path or "").strip()
    if not _DIR.match(text):
        raise DockerLogError("Log directory must be an absolute path without spaces.")
    parts = [part for part in text.split("/") if part]
    if ".." in parts:
        raise DockerLogError("Log directory cannot contain ..")
    if ".cache" in parts:
        raise DockerLogError("Log directory cannot be inside .cache.")
    return "/" + "/".join(parts)


def validate_server_fields(name: str, ssh_host: str, ssh_user: str, ssh_port, log_dir: str) -> dict:
    """Check the fields an operator types when adding a docker server."""
    cleaned_name = (name or "").strip()
    host = (ssh_host or "").strip()
    user = (ssh_user or "").strip()
    directory = validate_log_dir(log_dir)
    if not _NAME.match(cleaned_name):
        raise DockerLogError("Name must start with a letter or digit and stay within 64 characters.")
    if not _HOST.match(host) or host.startswith("-"):
        raise DockerLogError("SSH host must be a hostname or IP address.")
    if not _USER.match(user):
        raise DockerLogError("SSH user must be a normal account name.")
    try:
        port = int(ssh_port if ssh_port not in (None, "") else 22)
    except (TypeError, ValueError):
        raise DockerLogError("SSH port must be a number.")
    if port < 1 or port > 65535:
        raise DockerLogError("SSH port must be between 1 and 65535.")
    return {
        "name": cleaned_name,
        "ssh_host": host,
        "ssh_user": user,
        "ssh_port": port,
        "log_dir": directory,
    }


def log_kind(basename: str) -> str:
    if basename not in LOG_NAMES:
        raise DockerLogError("Only cve-check.log, update.log, and their .1 copies are read.")
    return "cve" if basename.startswith("cve-check") else "update"


def _cap(severity: int, catchup: bool) -> int:
    """History already on disk is stored, and it does not page Telegram."""
    if catchup and severity > 3:
        return 3
    return severity


def _event(server_id, source_host, source_ip, user, client_id, site_id,
           timestamp, body, event_type, severity, category, signature=None, action=None,
           display=None):
    """Identity stays the original log line. display is what an operator reads."""
    identity = f"{server_id}|{category}|{timestamp}|{body}"
    shown = display if display else body
    if len(shown) > 4000:
        shown = shown[:3997] + "..."
    return {
        "event_id": str(uuid.uuid5(EVENT_NAMESPACE, identity)),
        "timestamp": timestamp,
        "source_host": source_host,
        "os_type": "DOCKER",
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip or "N/A",
        "user": user or "system",
        "raw_message": shown,
        "client_id": client_id,
        "site_id": site_id,
        "signature": signature,
        "category": category,
        "action": action,
    }


_STEP = re.compile(r"^#\d+\s+")
_BUILD_PREFIX = re.compile(
    r"^(?:ERROR:\s*)?(?:failed to build:\s*)?(?:failed to solve:\s*)?"
    r"(?:failed to resolve source metadata for \S+:\s*)?"
)
_CLOSER = re.compile(
    r"^(?:===== done failures=\d+ ====="
    r"|updater exited\s+-?\d+.*"
    r"|updater finished\b.*"
    r"|no security update needed\b.*"
    r"|baseline refreshed\b.*)$"
)


def _clean_build_detail(body: str) -> str:
    """Drop BuildKit step numbers and the repeated 'failed to build' wrapper."""
    text = _STEP.sub("", (body or "").strip())
    previous = None
    while text and text != previous:
        previous = text
        text = _BUILD_PREFIX.sub("", text).strip()
    return text


def _unique_details(lines: list) -> list:
    """Keep the longest distinct error lines. A shorter copy of the same error goes."""
    cleaned = []
    for line in lines:
        text = _clean_build_detail(line)
        if text and text not in cleaned:
            cleaned.append(text)
    kept = []
    for text in cleaned:
        if any(text != other and text in other for other in cleaned):
            continue
        kept.append(text)
    return kept


def _fail_display(body: str, details: list) -> str:
    extra = _unique_details(details)
    if not extra:
        return body
    return body + "\n" + "\n".join(extra)


def _summary_display(body: str, cve_ids: list) -> str:
    if not cve_ids:
        return body
    lines = [body, "New advisories:"]
    lines.extend(cve_ids[:40])
    if len(cve_ids) > 40:
        lines.append(f"... and {len(cve_ids) - 40} more")
    return "\n".join(lines)


def is_docker_run_closer(body: str) -> bool:
    """A line that ends one CVE check or stack update."""
    return bool(_CLOSER.match((body or "").strip()))


def is_docker_run_fragment(event: dict) -> bool:
    """True when this row should share one Telegram message with the rest of its run.

    A rollback is its own incident and is sent on its own.
    """
    if (event.get("os_type") or "") != "DOCKER":
        return False
    if event.get("category") not in ("docker-cve", "docker-update"):
        return False
    if "rollback failed" in (event.get("raw_message") or ""):
        return False
    return True


def _event_moment(event: dict, field: str):
    value = event.get(field)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None


def docker_run_decision(events: list, *, now: datetime, timeout: timedelta,
                        severity_min: int = 4) -> tuple:
    """Decide whether one host's open docker rows are ready for a single alert.

    Returns (action, rows). action is "wait", "send", or "ignore".
    "ignore" marks closers that have no finding left to describe.
    """
    content = []
    closers = []
    for event in events:
        body = (event.get("raw_message") or "").strip()
        if is_docker_run_closer(body):
            closers.append(event)
            continue
        if "rollback failed" in body:
            continue
        if int(event.get("severity") or 0) >= severity_min:
            content.append(event)
    if not content:
        return "ignore", closers
    earliest = min((event.get("timestamp") or "") for event in content)
    closed = any((event.get("timestamp") or "") >= earliest for event in closers)
    oldest = None
    for event in content:
        moment = _event_moment(event, "created_at")
        if moment is not None and (oldest is None or moment < oldest):
            oldest = moment
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    timed_out = oldest is not None and (now - oldest) >= timeout
    if not closed and not timed_out:
        return "wait", []
    chosen_closers = [
        event for event in closers
        if (event.get("timestamp") or "") >= earliest
    ]
    return "send", content + chosen_closers


def _outcome_sentence(closers: list, has_failures: bool) -> str:
    failed = False
    clean = False
    for body in closers:
        done = _DONE.match(body)
        exited = _UPDATER_EXIT.match(body)
        if done and int(done.group(1)) > 0:
            failed = True
        elif done:
            clean = True
        if exited and int(exited.group(1)) != 0:
            failed = True
        elif exited:
            clean = True
        if body.startswith(("updater finished", "no security update needed", "baseline refreshed")):
            clean = True
    if failed or (clean and has_failures):
        return "The updater did not finish cleanly. The CVE baseline was kept, so this will be tried again."
    if clean:
        return "The updater finished without failures."
    return "The updater had not reported a result yet."


def describe_docker_run(host: str, events: list) -> str:
    """One plain-text Telegram body for a CVE check and the update it started."""
    advisories = []
    failures = []
    closers = []
    for event in events:
        body = (event.get("raw_message") or "").strip()
        if not body:
            continue
        if is_docker_run_closer(body):
            closers.append(body)
            continue
        if body.startswith("fixable high/critical"):
            advisories.append(body)
            continue
        if body.startswith("security update needed"):
            continue
        if int(event.get("severity") or 0) >= 4:
            failures.append(body)

    parts = [f"🔴 Docker update on {host}"]
    for block in advisories:
        lines = [line for line in block.splitlines() if line.strip()]
        summary = lines[0] if lines else block
        cves = [line for line in lines[1:] if line != "New advisories:"]
        parts.append("")
        parts.append(summary)
        if cves:
            parts.append("New advisories:")
            parts.extend(cves)
    if failures:
        noun = "failure" if len(failures) == 1 else "failures"
        parts.append("")
        parts.append(f"{len(failures)} {noun}:")
        for body in failures:
            head, _, detail = body.partition("\n")
            label = head[5:].strip() if head.startswith("FAIL ") else head
            parts.append("")
            parts.append(label)
            if detail.strip():
                parts.append(detail.strip())
    parts.append("")
    parts.append(_outcome_sentence(closers, bool(failures)))
    text = "\n".join(parts).strip()
    if len(text) > 3500:
        text = text[:3497] + "..."
    return text


_RUN_GAP = timedelta(hours=3)
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)
_ADVISORY = re.compile(r"^(?:CVE|GHSA)-[A-Za-z0-9][A-Za-z0-9-]*$")
_DOCKER_LINE = re.compile(
    r"^(?:===== |"
    r"updater exited\s+-?\d+|"
    r"updater finished\b|"
    r"no security update needed\b|"
    r"baseline refreshed\b|"
    r"security update needed\b|"
    r"fixable high/critical:|"
    r"fresh\s+(?:CVE|GHSA)-|"
    r"FAIL\b|"
    r"ERROR:|"
    r"#\d+\s+|"
    r"START\s+|"
    r"OK\s+|"
    r"scan\b|"
    r"check registry\b)"
)
_PROGRESS = (
    "===== CVE check start",
    "===== CVE check done",
    "===== docker stack update start",
    "START ",
    "OK ",
    "scan ",
    "check registry ",
    "recorded baseline",
    "no update on the first scan",
    "open=",
    "dry-run, updater not started",
    "another update is already running",
    "another CVE check is already running",
    "rolling back",
    "restore ",
)


def _moment(event: dict):
    """UTC time of a stored row. Log timestamps are text."""
    value = event.get("timestamp")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_line(body: str) -> str:
    text = (body or "").strip()
    if not text:
        return ""
    return text.splitlines()[0].strip()


def _closer_text(body: str) -> str:
    first = _first_line(body)
    if is_docker_run_closer(first):
        return first
    return ""


def _starts_new_scan(body: str) -> bool:
    return _first_line(body).startswith("===== CVE check start")


def _is_docker_view_row(event: dict) -> bool:
    """A stored docker log line that belongs in a run, including older rows with no category."""
    if not isinstance(event, dict):
        return False
    if (event.get("os_type") or "") != "DOCKER":
        return False
    if "rollback failed" in (event.get("raw_message") or ""):
        return False
    if is_docker_run_fragment(event):
        return True
    if event.get("category"):
        return False
    return bool(_DOCKER_LINE.match(_first_line(event.get("raw_message") or "")))


def _is_progress(first: str) -> bool:
    if first.startswith("scan failed") or first.startswith("incomplete scan"):
        return False
    return first.startswith(_PROGRESS)


def _is_build_detail(first: str, event: dict) -> bool:
    if first.startswith("FAIL") or first.startswith("====="):
        return False
    if event.get("event_type") == "CRITICAL_ERROR":
        return True
    if first.startswith("ERROR:") or _STEP.match(first):
        return True
    return "failed" in first.lower()


def _remember_advisory(found: list, value: str):
    text = (value or "").strip()
    if _ADVISORY.match(text) and text not in found:
        found.append(text)


def _park_details(failures: list, notable: list, pending: list) -> list:
    """Attach build lines that arrived before a FAIL. Leftovers stay visible."""
    if not pending:
        return []
    extra = _unique_details(pending)
    if failures:
        head, details = failures[-1]
        failures[-1] = (head, _unique_details(list(details) + extra))
        return []
    notable.extend(extra)
    return []


def _lead_line(failures: list, summary: str, failed: bool) -> str:
    """The table shows the first 100 characters, so the opening line stands alone."""
    if failures:
        count = len(failures)
        noun = "failure" if count == 1 else "failures"
        lead = f"{count} docker update {noun}."
        if failed:
            lead += " Baseline kept."
        if summary and len(f"{lead} {summary}") <= 100:
            lead = f"{lead} {summary}"
        return lead
    if summary:
        if failed and len(f"{summary} Baseline kept.") <= 100:
            return f"{summary} Baseline kept."
        return summary
    return ""


def _group_message(events: list) -> str:
    """One readable body: summary, each failed image, and the outcome."""
    summaries = []
    advisories = []
    failures = []
    pending = []
    closers = []
    notable = []
    for event in events:
        body = (event.get("raw_message") or "").strip()
        if not body:
            continue
        first = _first_line(body)
        _remember_advisory(advisories, event.get("signature") or "")
        closer = _closer_text(body)
        if closer:
            pending = _park_details(failures, notable, pending)
            closers.append(closer)
            continue
        if first.startswith("security update needed"):
            continue
        if first.startswith("fixable high/critical"):
            lines = [line.strip() for line in body.splitlines() if line.strip()]
            summaries.append(lines[0])
            for line in lines[1:]:
                if line != "New advisories:":
                    _remember_advisory(advisories, line)
            continue
        fresh = _FRESH.match(first)
        if fresh:
            _remember_advisory(advisories, fresh.group(1))
            continue
        if first.startswith("FAIL"):
            head, _, detail = body.partition("\n")
            details = _unique_details(pending + ([detail] if detail.strip() else []))
            pending = []
            failures.append((head.strip(), details))
            continue
        if first.startswith("scan failed") or first.startswith("incomplete scan"):
            notable.append(body)
            continue
        if _is_progress(first):
            continue
        if _is_build_detail(first, event):
            pending.append(body)
            continue
        if int(event.get("severity") or 0) >= 3:
            notable.append(body)
    _park_details(failures, notable, pending)

    summary = summaries[-1] if summaries else ""
    sentence = _outcome_sentence(closers, bool(failures)) if closers else ""
    failed = "did not finish cleanly" in sentence
    lead = _lead_line(failures, summary, failed)
    if not lead:
        if sentence and "had not reported" not in sentence:
            lead = sentence
        elif notable:
            lead = _first_line(notable[0])
            if len(lead) > 100:
                lead = lead[:97] + "..."
        else:
            lead = "Docker update is still running."

    parts = [lead]
    for head, details in failures:
        label = head[5:].strip() if head.startswith("FAIL ") else head
        parts.append("")
        parts.append(label)
        if details:
            parts.append("\n".join(details))
    for item in summaries:
        if item not in lead:
            parts.append(item)
    if advisories:
        parts.append("New advisories:")
        parts.extend(advisories[:40])
        if len(advisories) > 40:
            parts.append(f"... and {len(advisories) - 40} more")
    for note in notable:
        if note == lead or _first_line(note) == lead:
            continue
        parts.append(note)
    if sentence and sentence not in lead:
        parts.append("")
        parts.append(sentence)
    text = "\n".join(parts).strip()
    if len(text) > 4000:
        text = text[:3997] + "..."
    return text


def _collapse_run(events: list) -> dict:
    """Copy the sharpest stored row and replace its text with the whole run."""
    best = max(events, key=lambda event: (int(event.get("severity") or 0), _moment(event) or _EPOCH))
    latest = max(events, key=lambda event: _moment(event) or _EPOCH)
    row = dict(best)
    row["raw_message"] = _group_message(events)
    row["timestamp"] = latest.get("timestamp")
    row["severity"] = max(int(event.get("severity") or 0) for event in events)
    kinds = {event.get("event_type") for event in events}
    if "CRITICAL_ERROR" in kinds:
        row["event_type"] = "CRITICAL_ERROR"
    elif "VULNERABILITY" in kinds:
        row["event_type"] = "VULNERABILITY"
    else:
        row["event_type"] = row.get("event_type") or "SYSTEM_ALERT"
    return row


def _split_runs(items: list) -> list:
    """Oldest-first rows for one host. A closer or a three-hour gap ends a run."""
    runs = []
    current = []
    previous = None
    closed = False
    for item in items:
        _index, event, moment = item
        body = event.get("raw_message") or ""
        gap = (
            current
            and previous is not None
            and moment is not None
            and (moment - previous) > _RUN_GAP
        )
        if gap or (current and _starts_new_scan(body)) or (current and closed and not _closer_text(body)):
            runs.append(current)
            current = []
            closed = False
            previous = None
        current.append(item)
        if _closer_text(body):
            closed = True
        if moment is not None:
            previous = moment
    if current:
        runs.append(current)
    return runs


def collapse_docker_runs(events: list) -> list:
    """Show one row for a CVE check and the update it started.

    The database keeps every log line. The event log, alerts, and the dashboard
    read this view, so one failure is not repeated once per BuildKit line, FAIL
    line, and updater closer. A run is the docker lines for one organization and
    host. It ends when the updater closes, when the next CVE check starts, or
    when the next line is more than three hours later. Other events, including
    a rollback, pass through unchanged.
    """
    if not events:
        return []
    occupied = {}
    buckets = {}
    for index, event in enumerate(events):
        if not _is_docker_view_row(event):
            occupied[index] = event
            continue
        key = (str(event.get("client_id") or ""), str(event.get("source_host") or ""))
        buckets.setdefault(key, []).append((index, event, _moment(event)))
    for items in buckets.values():
        items.sort(key=lambda item: (item[2] or _EPOCH, item[0]))
        for run in _split_runs(items):
            if len(run) == 1:
                occupied[run[0][0]] = run[0][1]
                continue
            newest = max(run, key=lambda item: (item[2] or _EPOCH, -item[0]))
            occupied[newest[0]] = _collapse_run([item[1] for item in run])
    return [occupied[index] for index in sorted(occupied)]


def parse_chunk(text: str, *, server_id: str, source_host: str, source_ip: str,
                user: str, client_id: str, site_id: str, basename: str,
                catchup: bool) -> list:
    """Turn complete log lines into Heimdall events. Incomplete input is ignored.

    BuildKit repeats one image failure across several lines. Those lines become
    one event whose text includes the error. Fresh advisory ids are attached to
    the scan summary. A following "security update needed" line is the same
    finding and stays at severity 1.
    """
    kind = log_kind(basename)
    category = "docker-cve" if kind == "cve" else "docker-update"
    current_ts = None
    raw_lines = text.splitlines()
    first_scan = any("no update on the first scan" in line for line in raw_lines)
    events = []
    fresh_ids = []
    noise = []
    summary_paging = False

    def emit(timestamp, body, event_type, severity, signature, action, display=None):
        events.append(_event(
            server_id, source_host, source_ip, user, client_id, site_id,
            timestamp, body, event_type, severity, category, signature, action,
            display=display,
        ))

    def flush_noise():
        nonlocal noise
        pending = noise
        noise = []
        for timestamp, body in pending:
            classified = _classify(body, kind, catchup, first_scan)
            if classified is None:
                continue
            event_type, severity, signature, action = classified
            emit(timestamp, body, event_type, severity, signature, action)

    def is_noise(body):
        if kind != "update" or body.startswith("FAIL") or body.startswith("====="):
            return False
        if "rollback failed" in body:
            return False
        classified = _classify_update(body, catchup)
        return classified is not None and classified[0] == "CRITICAL_ERROR"

    for raw in raw_lines:
        stamped = _TS.match(raw.strip())
        if stamped:
            current_ts = stamped.group(1)
            body = stamped.group(2).strip()
        else:
            body = raw.strip()
            if not body or current_ts is None:
                continue
        if not body:
            continue
        if is_noise(body):
            noise.append((current_ts, body))
            continue
        classified = _classify(body, kind, catchup, first_scan)
        if classified is None:
            continue
        event_type, severity, signature, action = classified
        display = None
        if body.startswith("FAIL"):
            display = _fail_display(body, [item[1] for item in noise])
            noise = []
        else:
            flush_noise()
        fresh = _FRESH.match(body)
        if fresh:
            fresh_ids.append(fresh.group(1))
        if _SUMMARY.match(body):
            display = _summary_display(body, fresh_ids)
            fresh_ids = []
            summary_paging = severity >= 4
        if body.startswith("security update needed") and summary_paging:
            severity = 1
        emit(current_ts, body, event_type, severity, signature, action, display=display)
    flush_noise()
    return events


def _classify(body: str, kind: str, catchup: bool, first_scan: bool):
    if kind == "cve":
        return _classify_cve(body, catchup, first_scan)
    return _classify_update(body, catchup)


def _classify_cve(body: str, catchup: bool, first_scan: bool):
    fresh = _FRESH.match(body)
    if fresh:
        return ("VULNERABILITY", 3, fresh.group(1), "detected")
    summary = _SUMMARY.match(body)
    if summary:
        new = int(summary.group(2))
        severity = 2
        event_type = "SYSTEM_ALERT"
        if new > 0:
            severity = 4
            event_type = "VULNERABILITY"
        if first_scan:
            severity = 3
        return (event_type, _cap(severity, catchup), None, "detected" if new else None)
    if body.startswith("===== CVE check start"):
        return ("SYSTEM_ALERT", 1, None, "scan")
    if body.startswith("===== CVE check done"):
        return ("SYSTEM_ALERT", 1, None, None)
    if body.startswith("scan failed"):
        return ("CRITICAL_ERROR", 3, None, "failed")
    if body.startswith("incomplete scan"):
        return ("SYSTEM_ALERT", 3, None, None)
    if body.startswith("security update needed"):
        return ("SYSTEM_ALERT", _cap(4, catchup), None, "update")
    exited = _UPDATER_EXIT.match(body)
    if exited:
        code = int(exited.group(1))
        if code != 0:
            return ("CRITICAL_ERROR", _cap(4, catchup), None, "failed")
        return ("SYSTEM_ALERT", 1, None, None)
    if "no update on the first scan" in body or body.startswith("recorded baseline"):
        return ("SYSTEM_ALERT", 2, None, None)
    if body.startswith("another CVE check is already running"):
        return ("SYSTEM_ALERT", 2, None, None)
    if body.startswith("no security update needed") or body.startswith("baseline refreshed"):
        return ("SYSTEM_ALERT", 1, None, None)
    if body.startswith("dry-run, updater not started"):
        return ("SYSTEM_ALERT", 2, None, None)
    if body.startswith("scan ") or body.startswith("check registry "):
        return ("SYSTEM_ALERT", 1, None, "scan")
    if body.startswith("updater finished"):
        return ("SYSTEM_ALERT", 1, None, None)
    if body.startswith("open=") or body.startswith("fresh "):
        return None
    return ("SYSTEM_ALERT", 1, None, None)


def _classify_update(body: str, catchup: bool):
    if body.startswith("===== docker stack update start"):
        return ("SYSTEM_ALERT", 1, None, "update")
    done = _DONE.match(body)
    if done:
        failures = int(done.group(1))
        if failures > 0:
            return ("CRITICAL_ERROR", _cap(4, catchup), None, "failed")
        return ("SYSTEM_ALERT", 1, None, None)
    if body.startswith("FAIL"):
        return ("CRITICAL_ERROR", _cap(4, catchup), None, "failed")
    if "rollback failed" in body:
        return ("CRITICAL_ERROR", _cap(5, catchup), None, "failed")
    if body.startswith("rolling back") or body.startswith("restore "):
        return ("SYSTEM_ALERT", 3, None, None)
    if body.startswith("another update is already running"):
        return ("SYSTEM_ALERT", 2, None, None)
    if "failed" in body:
        return ("CRITICAL_ERROR", _cap(4, catchup), None, "failed")
    if body.startswith("OK ") or body.startswith("START "):
        return ("SYSTEM_ALERT", 1, None, None)
    if body.startswith("===== done"):
        return ("SYSTEM_ALERT", 1, None, None)
    return ("SYSTEM_ALERT", 1, None, None)


def reader_script() -> str:
    """The shell reader installed on a docker server and sent over SSH."""
    path = os.path.join(os.path.dirname(__file__), "..", "deploy", "heimdall-docker-logs")
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()
