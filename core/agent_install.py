"""Serve the one-command agent installers and the files they download."""

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "agents"
PLACEHOLDER = "__HEIMDALL_HUB_URL__"

SCRIPTS = {
    "linux": AGENTS / "install_linux_agent.sh",
    "macos": AGENTS / "install_macos_agent.sh",
    "windows": AGENTS / "Install-HeimdallAgent.ps1",
}

FILES = {
    "agent_linux.py": AGENTS / "agent_linux.py",
    "agent_macos.py": AGENTS / "agent_macos.py",
    "agent_firewall.py": AGENTS / "agent_firewall.py",
    "agent_pihole.py": AGENTS / "agent_pihole.py",
    "runtime.py": AGENTS / "runtime.py",
    "agent_windows.ps1": AGENTS / "agent_windows.ps1",
}

router = APIRouter(tags=["Install"])


def hub_base(request: Request) -> str:
    """Public hub URL baked into a downloaded installer."""
    configured = os.getenv("SIEM_PUBLIC_URL", "").strip().rstrip("/")
    if configured:
        return configured
    return str(request.base_url).rstrip("/")


def render_script(platform: str, hub_url: str) -> str:
    path = SCRIPTS[platform]
    text = path.read_text(encoding="utf-8")
    return text.replace(PLACEHOLDER, hub_url.rstrip("/"))


def agent_file(name: str) -> Path | None:
    path = FILES.get(name)
    if path is None or not path.is_file():
        return None
    return path


@router.get("/install/linux")
async def install_linux(request: Request):
    body = render_script("linux", hub_base(request))
    return PlainTextResponse(body)


@router.get("/install/macos")
async def install_macos(request: Request):
    body = render_script("macos", hub_base(request))
    return PlainTextResponse(body)


@router.get("/install/windows")
async def install_windows(request: Request):
    body = render_script("windows", hub_base(request))
    return PlainTextResponse(body)


@router.get("/install/files/{name}")
async def install_file(name: str):
    path = agent_file(name)
    if path is None:
        raise HTTPException(status_code=404, detail="Unknown install file")
    return PlainTextResponse(path.read_text(encoding="utf-8"))
