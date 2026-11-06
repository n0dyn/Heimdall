# Heimdall agent installation

The hub is already running. On each machine, one command installs the agent, starts it on boot, and checks in.

You need:

- The hub URL, including the port. The shipped hub listens on **8010**.
- The hub API key.
- Administrator rights on the machine (sudo, or an elevated PowerShell).

The installer writes one config file and refuses the default key `default-insecure-key-change-me`. It is finished only after `GET /health` and `POST /heartbeat` both succeed. Run the same command again to upgrade. The config file and the agent state are kept.

| System | Config file | Service |
|---|---|---|
| Linux, firewall, Pi-hole | `/etc/heimdall/agent.env` | `heimdall-agent` (systemd) |
| macOS | `/etc/heimdall/agent.env` | `com.heimdall.agent` (LaunchDaemon) |
| Windows | `C:\ProgramData\Heimdall\agent.env` | `HeimdallAgent` |

Optional flags on every installer: `--hostname NAME` (Windows: `-Hostname`) and `--interval SECONDS` (Windows: `-Interval`). The hostname is what the dashboard shows. When you leave it out, the agent uses the machine's own hostname. Linux also takes `--site NAME` (default `default`). A short site name such as `office` is stored on the hub as `<org-id>-office`.

## Linux

```bash
curl -fsSL http://YOUR_HUB_IP:8010/install/linux | sudo bash -s -- --key YOUR_API_KEY --site office
```

Firewall and Pi-hole use the same command with a role:

```bash
curl -fsSL http://YOUR_HUB_IP:8010/install/linux | sudo bash -s -- --key YOUR_API_KEY --site office --role firewall --firewall-type ufw
curl -fsSL http://YOUR_HUB_IP:8010/install/linux | sudo bash -s -- --key YOUR_API_KEY --site office --role pihole
```

`--firewall-type` is `iptables`, `ufw`, `pfsense`, `opnsense`, or `generic`. Add `--firewall-log /path/to/log` when the log is not in the default place. Pi-hole reads `/etc/pihole/pihole-FTL.db` unless you pass `--pihole-db`.

```bash
systemctl status heimdall-agent
journalctl -u heimdall-agent -f
curl -fsSL http://YOUR_HUB_IP:8010/install/linux | sudo bash -s -- --uninstall
```

From a copy of the repo, `sudo ./agents/install_linux_agent.sh --url http://YOUR_HUB_IP:8010 --key YOUR_API_KEY --site office` does the same thing. The positional form is `URL KEY [SITE] [HOSTNAME] [INTERVAL]`.

## macOS

Install Python 3.10+ from [python.org](https://www.python.org/downloads/macos/) first. Then:

```bash
curl -fsSL http://YOUR_HUB_IP:8010/install/macos | sudo bash -s -- --key YOUR_API_KEY
```

```bash
tail -f /var/log/heimdall-agent.log
curl -fsSL http://YOUR_HUB_IP:8010/install/macos | sudo bash -s -- --uninstall
```

Auth logs stay empty until Python has Full Disk Access. Open System Settings, Privacy & Security, Full Disk Access, and enable `/opt/heimdall/venv/bin/python`. Then:

```bash
sudo launchctl kickstart -k system/com.heimdall.agent
```

From a copy of the repo: `sudo ./agents/install_macos_agent.sh --url http://YOUR_HUB_IP:8010 --key YOUR_API_KEY`.

## Windows

Open PowerShell as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-RestMethod http://YOUR_HUB_IP:8010/install/windows))) -ApiKey YOUR_API_KEY"
```

The installer downloads `agent_windows.ps1` and registers it as a SYSTEM scheduled task. Windows PowerShell runs that script. It is already on the machine, and Application Control allows it. The install does not run `HeimdallAgent.exe`, and Windows does not need Python. `-Hostname` is written to `agent.env` and the agent reports that name.

Logs are in `C:\ProgramData\Heimdall\logs`. To remove the service and keep the config file, run the installer again with `-Uninstall`.

A copy of the repo can be installed with `install_agent.bat` or:

```powershell
powershell -ExecutionPolicy Bypass -File .\agents\Install-HeimdallAgent.ps1 -ApiUrl http://YOUR_HUB_IP:8010 -ApiKey YOUR_API_KEY
```

## Config file

```bash
SIEM_API_URL=http://YOUR_HUB_IP:8010
SIEM_API_KEY=YOUR_API_KEY
SIEM_SITE_ID=office
SIEM_INTERVAL=30
SIEM_ROLE=linux
SIEM_HOSTNAME=host-42
SIEM_STATE_DIR=/var/lib/heimdall
```

`SIEM_HOSTNAME` is written only when you pass a hostname. Linux log paths still go in `SIEM_LOG_FILES` (comma-separated). Firewall log and type are `FIREWALL_LOG_PATH` and `FIREWALL_TYPE`. Pi-hole's database is `SIEM_PIHOLE_DB_PATH`.

Restart after an edit: `sudo systemctl restart heimdall-agent`, `sudo launchctl kickstart -k system/com.heimdall.agent`, or on Windows `schtasks /End /TN HeimdallAgent` followed by `schtasks /Run /TN HeimdallAgent`.

## What the hub serves

These routes are public. The API key is not required to download the installer. The agent uses the key after it is installed.

- `GET /install/linux`
- `GET /install/macos`
- `GET /install/windows`
- `GET /install/files/<agent file>`

Set `SIEM_PUBLIC_URL` on the hub when it is behind a proxy, so the downloaded script carries the address agents can reach.

## Action1

On the hub's Action1 page, sync the organization, check the Windows, Mac, and Linux endpoints, and choose **Install Heimdall agent**. Action1 runs the installer once. Sync does not install the agent, and the software catalog is not used.

The hub writes the hub URL and API key into that run. Bash scripts cannot take Action1 parameters, so the key stays in the one-time script and is left out of the page response. Offline computers are retried for 24 hours. The computer stays up.

The Linux role on that form applies to every checked Linux endpoint. `firewall` and `pihole` are Linux roles. Windows and Mac keep their own installers. macOS still needs Python 3.10 or newer, and Full Disk Access after the install.

Each endpoint downloads the installer from the hub:

- Windows: `GET /install/windows`
- macOS: `GET /install/macos`
- Linux: `GET /install/linux`

Those routes have to be on the hub the endpoints can reach. Set **Hub URL for the endpoints** when that address is not `http://<this-server>:8010`.

`agents/action1/Install-Heimdall.ps1` and `agents/action1/install-heimdall.sh` are the same commands for a manual Action1 paste. Prefer the hub button so the API key is not saved in the Script Library.
