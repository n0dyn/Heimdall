"""Install the Heimdall agent through a one-shot Action1 Run Script.

Action1 can run PowerShell on Windows and Bash on Mac and Linux. Deploy
Software does not cover Linux, and Bash scripts cannot take parameters, so
the hub writes the hub URL and API key into the script for that run. The
value returned to the dashboard never includes the script text.

Sync does not call this. The operator picks endpoints and launches it.
"""

import os
import urllib.parse

from pydantic import BaseModel, Field

from .action1_client import Action1Client, Action1Error
from .action1_store import get_endpoint
from .action1_sync import client_from_settings


INSECURE_API_KEY = "default-insecure-key-change-me"
LINUX_ROLES = ("linux", "firewall", "pihole")
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "testserver"}
_PLATFORM = {
    "windows": "windows",
    "mac": "macos",
    "macos": "macos",
    "linux": "linux",
}
_ACTION1_PLATFORM = {"windows": "Windows", "macos": "Mac", "linux": "Linux"}
_LANGUAGE = {"windows": "PowerShell", "macos": "Bash", "linux": "Bash"}
_PLATFORM_ORDER = {"windows": 0, "macos": 1, "linux": 2}


class AgentDeployRequest(BaseModel):
    endpoints: list = Field(default_factory=list)
    hostname: str = ""
    role: str = ""
    hub_url: str = ""


def normalize_platform(value: str) -> str:
    return _PLATFORM.get(str(value or "").strip().lower(), "")


def normalize_role(value: str) -> str:
    role = str(value or "").strip().lower()
    if not role:
        return "linux"
    if role not in LINUX_ROLES:
        raise Action1Error(400, "Linux role must be linux, firewall, or pihole")
    return role


def _no_controls(value: str, label: str) -> str:
    if any(ord(char) < 32 for char in value):
        raise Action1Error(400, f"{label} cannot contain a line break or control character")
    return value


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def bash_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def resolve_hub_url(explicit: str = "", public_url: str = "", fallback: str = "") -> str:
    """Address the endpoint can use to download the installer."""
    chosen = (explicit or "").strip()
    if not chosen:
        chosen = (public_url or "").strip() or (os.getenv("SIEM_PUBLIC_URL") or "").strip()
    if not chosen:
        chosen = (fallback or "").strip()
    if not chosen:
        raise Action1Error(400, "A hub URL that endpoints can reach is required")
    chosen = _no_controls(chosen, "Hub URL").rstrip("/")
    parsed = urllib.parse.urlsplit(chosen)
    host = (parsed.hostname or "").lower().strip("[]")
    if parsed.scheme not in ("http", "https") or not host:
        raise Action1Error(400, "Hub URL must be an http or https address")
    if host in _BLOCKED_HOSTS:
        raise Action1Error(400, "Hub URL must be an address the endpoints can reach")
    return chosen


def agent_api_key(explicit: str = None) -> str:
    key = explicit if explicit is not None else (os.getenv("SIEM_API_KEY") or "")
    key = _no_controls(str(key).strip(), "API key")
    if not key:
        raise Action1Error(400, "Set SIEM_API_KEY before installing agents")
    if key == INSECURE_API_KEY:
        raise Action1Error(400, "SIEM_API_KEY is still the default. Set a private key before installing agents")
    return key


def normalize_hostname(value: str) -> str:
    hostname = _no_controls(str(value or "").strip(), "Hostname")
    if not hostname:
        return ""
    if len(hostname) > 253 or not hostname[0].isalnum():
        raise Action1Error(400, "Hostname must start with a letter or number")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if any(char not in allowed for char in hostname):
        raise Action1Error(400, "Hostname can use letters, numbers, dots, and hyphens")
    return hostname


def _join(hub: str, path: str) -> str:
    return hub.rstrip("/") + "/" + path.lstrip("/")


def windows_script(hub: str, api_key: str, hostname: str) -> str:
    """Install agent_windows.ps1. Do not run HeimdallAgent.exe.

    Application Control on the endpoint blocks that unsigned exe. Windows
    PowerShell is already installed and is what Action1 itself is allowed to run.
    """
    host_line = f"$Hostname = {ps_quote(hostname)}" if hostname else "$Hostname = $env:COMPUTERNAME"
    lines = [
        "$ErrorActionPreference = 'Stop'",
        # Action1 runs this in session 0. The progress bar breaks the download.
        "$ProgressPreference = 'SilentlyContinue'",
        "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}",
        f"$ApiUrl = {ps_quote(hub)}",
        f"$ApiKey = {ps_quote(api_key)}",
        host_line,
        "$InstallPath = Join-Path $env:ProgramData 'Heimdall'",
        "$LogDir = Join-Path $InstallPath 'logs'",
        "New-Item -ItemType Directory -Force -Path $InstallPath, $LogDir | Out-Null",
        # Stop a copy that is already running so Windows will let us replace the script.
        "$pref = $ErrorActionPreference",
        "$ErrorActionPreference = 'Continue'",
        "cmd.exe /c \"sc stop HeimdallAgent >nul 2>&1 & sc delete HeimdallAgent >nul 2>&1 & schtasks /End /TN HeimdallAgent >nul 2>&1 & schtasks /Delete /TN HeimdallAgent /F >nul 2>&1\" | Out-Null",
        "$ErrorActionPreference = $pref",
        "$dest = Join-Path $InstallPath 'agent_windows.ps1'",
        "$uri = $ApiUrl.TrimEnd('/') + '/install/files/agent_windows.ps1'",
        "$request = [System.Net.HttpWebRequest]::Create($uri)",
        "$request.Method = 'GET'",
        "$request.UserAgent = 'HeimdallInstaller'",
        "$request.Timeout = 180000",
        "$request.ReadWriteTimeout = 180000",
        "$response = $request.GetResponse()",
        "try {",
        "    $out = [System.IO.File]::Create($dest)",
        "    try { $response.GetResponseStream().CopyTo($out) } finally { $out.Close() }",
        "} finally { $response.Close() }",
        "if ((Get-Item $dest).Length -lt 100) { throw 'Downloaded agent_windows.ps1 is empty.' }",
        "$envLines = @(",
        "    \"SIEM_API_URL=$ApiUrl\",",
        "    \"SIEM_API_KEY=$ApiKey\",",
        "    'SIEM_INTERVAL=60',",
        "    'SIEM_AGENT_INTERVAL=60',",
        "    'SIEM_ROLE=windows',",
        "    \"SIEM_HOSTNAME=$Hostname\",",
        "    \"SIEM_STATE_DIR=$LogDir\",",
        "    \"HEIMDALL_LOG_DIR=$LogDir\",",
        "    \"HEIMDALL_HOME=$InstallPath\"",
        ")",
        "Set-Content -Path (Join-Path $InstallPath 'agent.env') -Value ($envLines -join \"`n\") -Encoding ASCII",
        "$runner = Join-Path $InstallPath 'run-agent.cmd'",
        "@(",
        "    '@echo off',",
        "    \"cd /d `\"$InstallPath`\"\",",
        "    ':loop',",
        "    \"powershell.exe -NoProfile -ExecutionPolicy Bypass -File `\"$dest`\"\",",
        "    'ping -n 11 127.0.0.1 >nul',",
        "    'goto loop'",
        ") | Set-Content -Path $runner -Encoding ASCII",
        # No nested quotes. schtasks accepts /Create and then fails to launch a /TR value that contains quotes.
        "$task = schtasks.exe /Create /F /TN HeimdallAgent /SC ONSTART /RU SYSTEM /RL HIGHEST /TR \"powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dest\"",
        "if ($LASTEXITCODE -ne 0) { throw \"Windows did not register the Heimdall agent task. $task\" }",
        "schtasks.exe /Run /TN HeimdallAgent | Out-Null",
        "if ($LASTEXITCODE -ne 0) { throw 'Windows did not start the Heimdall agent task.' }",
    ]
    return "\n".join(lines) + "\n"


def unix_script(hub: str, api_key: str, hostname: str, platform: str, role: str) -> str:
    route = "macos" if platform == "macos" else "linux"
    lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        f"api_url={bash_quote(hub)}",
        f"api_key={bash_quote(api_key)}",
        "args=(--url \"$api_url\" --key \"$api_key\")",
    ]
    if hostname:
        lines.append(f"hostname={bash_quote(hostname)}")
        lines.append("args+=(--hostname \"$hostname\")")
    if platform == "linux":
        lines.append(f"role={bash_quote(role)}")
        lines.append("args+=(--role \"$role\")")
    lines.append(
        f"curl -fsSL \"${{api_url%/}}/install/{route}\" | bash -s -- \"${{args[@]}}\""
    )
    return "\n".join(lines) + "\n"


def instance_body(name: str, endpoint_ids: list, script: str, language: str, platform: str) -> dict:
    return {
        "name": name,
        "retry_minutes": "1440",
        "endpoints": [{"id": endpoint_id, "type": "Endpoint"} for endpoint_id in endpoint_ids],
        "actions": [{
            "name": "Install Heimdall agent",
            "template_id": "run_script",
            "params": {
                "display_summary": "Install the Heimdall agent",
                "condition_script_text": "",
                "condition_script_language": language,
                "run_script_params": [],
                "run_script_text": script,
                "run_script_language": language,
                "platform": _ACTION1_PLATFORM[platform],
                "reboot_exit_codes": "",
                "reboot_options": {"auto_reboot": "no"},
            },
        }],
    }


def _endpoint_pairs(raw) -> list:
    if not isinstance(raw, list) or not raw:
        raise Action1Error(400, "Select at least one endpoint")
    seen = set()
    pairs = []
    for item in raw:
        if not isinstance(item, dict):
            raise Action1Error(400, "Each endpoint needs an organization and an endpoint id")
        org_id = str(item.get("action1_org_id") or "").strip()
        endpoint_id = str(item.get("endpoint_id") or "").strip()
        if not org_id or not endpoint_id:
            raise Action1Error(400, "Each endpoint needs an organization and an endpoint id")
        _no_controls(org_id, "Organization id")
        _no_controls(endpoint_id, "Endpoint id")
        if org_id.lower() == "all":
            raise Action1Error(400, "Choose endpoints in one organization. Action1 rejects an install aimed at all organizations")
        key = (org_id, endpoint_id)
        if key in seen:
            continue
        seen.add(key)
        pairs.append(key)
    return pairs


def build_jobs(rows: list, hub_url: str, api_key: str, hostname: str = "", role: str = "") -> dict:
    """Group one install instance per organization and platform. The public half has no script."""
    hub = resolve_hub_url(hub_url)
    key = agent_api_key(api_key)
    host = normalize_hostname(hostname)
    linux_role = normalize_role(role)
    grouped = {}
    skipped = []
    for row in rows:
        platform = normalize_platform(row.get("platform"))
        if not platform:
            skipped.append({
                "action1_org_id": row.get("action1_org_id") or "",
                "endpoint_id": row.get("endpoint_id") or "",
                "name": row.get("name") or row.get("endpoint_id") or "",
                "platform": row.get("platform") or "",
                "reason": "Heimdall installs through Action1 on Windows, Mac, and Linux",
            })
            continue
        org_id = row["action1_org_id"]
        bucket = grouped.setdefault((org_id, platform), [])
        bucket.append(row)

    jobs = []
    for (org_id, platform) in sorted(grouped, key=lambda item: (item[0], _PLATFORM_ORDER[item[1]])):
        selected = grouped[(org_id, platform)]
        language = _LANGUAGE[platform]
        if platform == "windows":
            script = windows_script(hub, key, host)
            title = "Install Heimdall agent (Windows)"
        elif platform == "macos":
            script = unix_script(hub, key, host, "macos", linux_role)
            title = "Install Heimdall agent (Mac)"
        else:
            script = unix_script(hub, key, host, "linux", linux_role)
            title = "Install Heimdall agent (Linux)" if linux_role == "linux" else f"Install Heimdall {linux_role} agent (Linux)"
        endpoint_ids = [row["endpoint_id"] for row in selected]
        jobs.append({
            "org": org_id,
            "body": instance_body(title, endpoint_ids, script, language, platform),
            "public": {
                "name": title,
                "action1_org_id": org_id,
                "platform": platform,
                "language": language,
                "endpoints": [
                    {"endpoint_id": row["endpoint_id"], "name": row.get("name") or row["endpoint_id"]}
                    for row in selected
                ],
            },
        })
    return {"hub_url": hub, "role": linux_role, "jobs": jobs, "skipped": skipped}


def _launched(job: dict, created) -> dict:
    public = dict(job["public"])
    instance_id = ""
    if isinstance(created, dict):
        instance_id = str(created.get("id") or "")
    public["id"] = instance_id
    return public


def deploy_agents(endpoints, hub_url: str = "", hostname: str = "", role: str = "",
                  api_key: str = None, fallback_url: str = "", client: Action1Client = None) -> dict:
    """Look up stored endpoints and start one Run Script instance per platform."""
    pairs = _endpoint_pairs(endpoints)
    # Validate the operator input before any Action1 call, including a bad hub URL.
    hub = resolve_hub_url(hub_url, fallback=fallback_url)
    key = agent_api_key(api_key)
    normalize_hostname(hostname)
    normalize_role(role)

    missing = 0
    rows = []
    for org_id, endpoint_id in pairs:
        row = get_endpoint(org_id, endpoint_id)
        if not row:
            missing += 1
            continue
        rows.append(row)
    if missing:
        detail = "Action1 endpoint was not found" if missing == 1 else "One or more Action1 endpoints were not found"
        raise Action1Error(404, detail)

    plan = build_jobs(rows, hub, key, hostname, role)
    if not plan["jobs"]:
        raise Action1Error(400, "None of the selected endpoints are Windows, Mac, or Linux")

    action1 = client or client_from_settings()
    launched = []
    try:
        for job in plan["jobs"]:
            created = action1.create_automation_instance(job["org"], job["body"])
            launched.append(_launched(job, created))
    except Action1Error as exc:
        if exc.status == 403 and "/automations/instances/" in (exc.detail or ""):
            sent = f" {len(launched)} install(s) were already sent." if launched else ""
            raise Action1Error(
                403,
                "Action1 denied the install. The saved role needs permission to run automations." + sent,
            )
        raise
    return {
        "hub_url": plan["hub_url"],
        "role": plan["role"],
        "instances": launched,
        "skipped": plan["skipped"],
    }
