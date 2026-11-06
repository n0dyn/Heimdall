#!/bin/bash
# Install the Heimdall agent on macOS.
#
# From the hub (the URL is filled in for you):
#   curl -fsSL http://HUB:8010/install/macos | sudo bash -s -- --key YOUR_KEY
#
# From a copy of this repo, on the Mac:
#   sudo ./install_macos_agent.sh --url http://HUB:8010 --key YOUR_KEY
#
# Re-running upgrades the agent and keeps the config.
#   sudo ./install_macos_agent.sh --uninstall

set -euo pipefail

INSTALL_DIR="/opt/heimdall"
CONFIG_DIR="/etc/heimdall"
CONFIG_FILE="$CONFIG_DIR/agent.env"
STATE_DIR="/var/lib/heimdall"
PLIST="/Library/LaunchDaemons/com.heimdall.agent.plist"
LABEL="com.heimdall.agent"
INSECURE_KEY="default-insecure-key-change-me"

# The hub replaces the token in HUB_URL when you download the script.
# The check is split so that replacement does not erase a real URL.
HUB_URL="__HEIMDALL_HUB_URL__"
PLACEHOLDER='__HEIMDALL_HUB''_URL__'
if [ "$HUB_URL" = "$PLACEHOLDER" ]; then
    HUB_URL=""
fi

API_URL=""
API_KEY=""
HOSTNAME_OVERRIDE=""
INTERVAL=""
UNINSTALL=0

usage() {
    cat <<'EOF'
Usage: install_macos_agent.sh --url http://HUB:8010 --key YOUR_KEY

Options:
  --url URL           Heimdall hub, including port
  --key KEY           API key from the hub
  --hostname NAME     Name to show on the dashboard (default: this Mac's hostname)
  --interval SECONDS  How often to report (default: 30)
  --uninstall         Stop the agent and remove the LaunchDaemon. Keeps the config file.

A saved /etc/heimdall/agent.env supplies any values you leave out.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --url) API_URL="${2:-}"; shift 2 ;;
        --key) API_KEY="${2:-}"; shift 2 ;;
        --hostname) HOSTNAME_OVERRIDE="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        --help|-h) usage; exit 0 ;;
        --) shift; break ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -z "$API_URL" ]; then
                API_URL="$1"
            elif [ -z "$API_KEY" ]; then
                API_KEY="$1"
            else
                echo "Unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

apply_saved() {
    [ -f "$CONFIG_FILE" ] || return 0
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|\#*) continue ;;
        esac
        key=${line%%=*}
        val=${line#*=}
        case "$key" in
            SIEM_API_URL) [ -z "$API_URL" ] && API_URL=$val ;;
            SIEM_API_KEY) [ -z "$API_KEY" ] && API_KEY=$val ;;
            SIEM_HOSTNAME) [ -z "$HOSTNAME_OVERRIDE" ] && HOSTNAME_OVERRIDE=$val ;;
            SIEM_INTERVAL) [ -z "$INTERVAL" ] && INTERVAL=$val ;;
        esac
    done < "$CONFIG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (sudo)." >&2
    exit 1
fi

apply_saved

if [ -z "$API_URL" ]; then
    API_URL="$HUB_URL"
fi
if [ -z "$INTERVAL" ]; then
    INTERVAL=30
fi

bootout_agent() {
    launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
}

if [ "$UNINSTALL" -eq 1 ]; then
    bootout_agent
    rm -f "$PLIST"
    echo "Removed $LABEL."
    echo "Left $CONFIG_FILE and $STATE_DIR in place."
    exit 0
fi

if [ -z "$API_URL" ] || [ -z "$API_KEY" ]; then
    echo "Need the hub URL and API key." >&2
    echo "Example: sudo $0 --url http://HUB:8010 --key YOUR_KEY" >&2
    exit 1
fi
case "$API_URL" in
    http://*|https://*) ;;
    *)
        echo "Hub URL must start with http:// or https://" >&2
        exit 1
        ;;
esac
API_URL="${API_URL%/}"
if [ "$API_KEY" = "$INSECURE_KEY" ]; then
    echo "Refusing the default API key. Pass the key from your hub." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.10+ is not installed." >&2
    echo "Install it from https://www.python.org/downloads/macos/ and run this again." >&2
    exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Python 3.10+ is required. Found: $(python3 --version 2>&1)" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required." >&2
    exit 1
fi

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
else
    SCRIPT_DIR=""
fi

echo "Installing Heimdall (macos) -> $API_URL"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"

if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/python" -m pip install --disable-pip-version-check requests 'python-dateutil'

copy_payload() {
    local name="$1"
    local dest="$INSTALL_DIR/$name"
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$name" ]; then
        cp "$SCRIPT_DIR/$name" "$dest"
        return
    fi
    echo "Downloading $name"
    curl -fsSL "$API_URL/install/files/$name" -o "$dest"
}

copy_payload "agent_macos.py"
copy_payload "runtime.py"
chmod 644 "$INSTALL_DIR/agent_macos.py" "$INSTALL_DIR/runtime.py"

umask 077
{
    printf 'SIEM_API_URL=%s\n' "$API_URL"
    printf 'SIEM_API_KEY=%s\n' "$API_KEY"
    printf 'SIEM_INTERVAL=%s\n' "$INTERVAL"
    printf 'SIEM_ROLE=%s\n' "macos"
    printf 'SIEM_STATE_DIR=%s\n' "$STATE_DIR"
    if [ -n "$HOSTNAME_OVERRIDE" ]; then
        printf 'SIEM_HOSTNAME=%s\n' "$HOSTNAME_OVERRIDE"
    fi
} > "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"

cat > "$INSTALL_DIR/run-agent.sh" <<EOF
#!/bin/bash
set -a
. "$CONFIG_FILE"
set +a
exec "$INSTALL_DIR/venv/bin/python" -u "$INSTALL_DIR/agent_macos.py"
EOF
chmod 755 "$INSTALL_DIR/run-agent.sh"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/run-agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/heimdall-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/heimdall-agent.err.log</string>
</dict>
</plist>
EOF
chmod 644 "$PLIST"

bootout_agent
if ! launchctl bootstrap system "$PLIST"; then
    launchctl load -w "$PLIST"
fi

if [ -n "$HOSTNAME_OVERRIDE" ]; then
    REPORT_HOST="$HOSTNAME_OVERRIDE"
else
    REPORT_HOST=$(hostname)
fi

HEALTH=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "$API_URL/health" || true)
if [ "$HEALTH" != "200" ]; then
    echo "Hub health check failed (HTTP ${HEALTH:-none}) at $API_URL/health" >&2
    echo "The agent is installed. Logs: tail -f /var/log/heimdall-agent.err.log" >&2
    exit 1
fi

HEARTBEAT=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "$API_URL/heartbeat" \
    -H "api-key: $API_KEY" \
    -H "source-host: $REPORT_HOST" \
    -H "os-type: MACOS" || true)
if [ "$HEARTBEAT" != "200" ]; then
    echo "Hub rejected the check-in (HTTP ${HEARTBEAT:-none}). Confirm the API key." >&2
    echo "Logs: tail -f /var/log/heimdall-agent.err.log" >&2
    exit 1
fi

echo "Heimdall is running as $REPORT_HOST (MACOS)."
echo "Logs:    tail -f /var/log/heimdall-agent.log"
echo "Config:  $CONFIG_FILE"
echo "Remove:  curl -fsSL $API_URL/install/macos | sudo bash -s -- --uninstall"
echo
echo "Log collection stays empty until Python has Full Disk Access:"
echo "  System Settings -> Privacy & Security -> Full Disk Access"
echo "  Enable $INSTALL_DIR/venv/bin/python"
echo "Then restart the agent:"
echo "  sudo launchctl kickstart -k system/$LABEL"
