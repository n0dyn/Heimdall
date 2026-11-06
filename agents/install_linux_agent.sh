#!/bin/bash
# Install the Heimdall agent on Linux.
#
# From the hub (the URL is filled in for you):
#   curl -fsSL http://HUB:8010/install/linux | sudo bash -s -- --key YOUR_KEY
#
# From a copy of this repo, on the target machine:
#   sudo ./install_linux_agent.sh --url http://HUB:8010 --key YOUR_KEY --site office
#
# Roles: linux (default), firewall, pihole
#   sudo ./install_linux_agent.sh --url http://HUB:8010 --key YOUR_KEY --role firewall --firewall-type ufw
#   sudo ./install_linux_agent.sh --url http://HUB:8010 --key YOUR_KEY --role pihole
#
# Older positional form still works:
#   sudo ./install_linux_agent.sh http://HUB:8010 YOUR_KEY office web-01 30
#
# Re-running the same command upgrades the agent and keeps the config.
#   sudo ./install_linux_agent.sh --uninstall

set -euo pipefail

INSTALL_DIR="/opt/heimdall"
CONFIG_DIR="/etc/heimdall"
CONFIG_FILE="$CONFIG_DIR/agent.env"
STATE_DIR="/var/lib/heimdall"
SERVICE_NAME="heimdall-agent"
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
SITE_NAME=""
HOSTNAME_OVERRIDE=""
ROLE=""
INTERVAL=""
FW_TYPE=""
FW_LOG=""
PIHOLE_DB=""
UNINSTALL=0

usage() {
    cat <<'EOF'
Usage: install_linux_agent.sh --url http://HUB:8010 --key YOUR_KEY [--site SITE] [--role linux|firewall|pihole]

Options:
  --url URL              Heimdall hub, including port
  --key KEY              API key from the hub
  --site SITE            Site inside the organization (default: default)
  --hostname NAME        Name to show on the dashboard (default: this machine's hostname)
  --role ROLE            linux (default), firewall, or pihole
  --interval SECONDS     How often to report (default: 30, or 60 for pihole)
  --firewall-type TYPE   iptables, ufw, pfsense, opnsense, or generic
  --firewall-log PATH    Log file to read for the firewall role
  --pihole-db PATH       Pi-hole FTL database (default: /etc/pihole/pihole-FTL.db)
  --uninstall            Stop the agent and remove the service. Keeps the config file.

A saved /etc/heimdall/agent.env supplies any values you leave out, so a
re-run upgrades the agent without typing the key again.

Positional form: install_linux_agent.sh URL KEY [SITE] [HOSTNAME] [INTERVAL]
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
        --site) SITE_NAME="${2:-}"; shift 2 ;;
        --hostname) HOSTNAME_OVERRIDE="${2:-}"; shift 2 ;;
        --role) ROLE="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --firewall-type) FW_TYPE="${2:-}"; shift 2 ;;
        --firewall-log) FW_LOG="${2:-}"; shift 2 ;;
        --pihole-db) PIHOLE_DB="${2:-}"; shift 2 ;;
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
            elif [ -z "$SITE_NAME" ]; then
                SITE_NAME="$1"
            elif [ -z "$HOSTNAME_OVERRIDE" ]; then
                HOSTNAME_OVERRIDE="$1"
            elif [ -z "$INTERVAL" ]; then
                INTERVAL="$1"
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
            SIEM_SITE_ID|SIEM_SITE) [ -z "$SITE_NAME" ] && SITE_NAME=$val ;;
            SIEM_HOSTNAME) [ -z "$HOSTNAME_OVERRIDE" ] && HOSTNAME_OVERRIDE=$val ;;
            SIEM_INTERVAL) [ -z "$INTERVAL" ] && INTERVAL=$val ;;
            SIEM_ROLE) [ -z "$ROLE" ] && ROLE=$val ;;
            FIREWALL_TYPE) [ -z "$FW_TYPE" ] && FW_TYPE=$val ;;
            FIREWALL_LOG_PATH) [ -z "$FW_LOG" ] && FW_LOG=$val ;;
            SIEM_PIHOLE_DB_PATH) [ -z "$PIHOLE_DB" ] && PIHOLE_DB=$val ;;
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
if [ -z "$ROLE" ]; then
    ROLE="linux"
fi

case "$ROLE" in
    linux) AGENT_SCRIPT="agent_linux.py"; OS_TYPE="LINUX" ;;
    firewall) AGENT_SCRIPT="agent_firewall.py"; OS_TYPE="FIREWALL" ;;
    pihole) AGENT_SCRIPT="agent_pihole.py"; OS_TYPE="PIHOLE" ;;
    *)
        echo "Unknown role: $ROLE (use linux, firewall, or pihole)" >&2
        exit 1
        ;;
esac

if [ -z "$INTERVAL" ]; then
    if [ "$ROLE" = "pihole" ]; then
        INTERVAL=60
    else
        INTERVAL=30
    fi
fi

remove_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload >/dev/null 2>&1 || true
    else
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    fi
}

if [ "$UNINSTALL" -eq 1 ]; then
    remove_service
    echo "Removed $SERVICE_NAME."
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
if [ -z "$SITE_NAME" ]; then
    SITE_NAME="default"
fi
case "$SITE_NAME" in
    *[!A-Za-z0-9._-]*)
        echo "Site name must use letters, numbers, dots, underscores, or hyphens." >&2
        exit 1
        ;;
esac
case "$INTERVAL" in
    *[!0-9]*)
        echo "Interval must be a number of seconds." >&2
        exit 1
        ;;
esac

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
else
    SCRIPT_DIR=""
fi

echo "Installing Heimdall ($ROLE) -> $API_URL"

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv ca-certificates curl
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip ca-certificates curl
    dnf install -y python3-virtualenv >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip ca-certificates curl
else
    command -v python3 >/dev/null 2>&1 || { echo "Install Python 3.10+ and re-run." >&2; exit 1; }
    command -v curl >/dev/null 2>&1 || { echo "Install curl and re-run." >&2; exit 1; }
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd is required. This installer cannot set up the service here." >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"

if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    rm -rf "$INSTALL_DIR/venv"
    if ! python3 -m venv "$INSTALL_DIR/venv"; then
        rm -rf "$INSTALL_DIR/venv"
        python3 -m virtualenv "$INSTALL_DIR/venv"
    fi
fi
"$INSTALL_DIR/venv/bin/python" -m pip install --disable-pip-version-check requests 'python-dateutil' psutil

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

copy_payload "$AGENT_SCRIPT"
copy_payload "runtime.py"
chmod 644 "$INSTALL_DIR/$AGENT_SCRIPT" "$INSTALL_DIR/runtime.py"

umask 077
{
    printf 'SIEM_API_URL=%s\n' "$API_URL"
    printf 'SIEM_API_KEY=%s\n' "$API_KEY"
    printf 'SIEM_SITE_ID=%s\n' "$SITE_NAME"
    printf 'SIEM_INTERVAL=%s\n' "$INTERVAL"
    printf 'SIEM_ROLE=%s\n' "$ROLE"
    printf 'SIEM_STATE_DIR=%s\n' "$STATE_DIR"
    printf 'HEIMDALL_STATE_DIR=%s\n' "$STATE_DIR"
    if [ -n "$HOSTNAME_OVERRIDE" ]; then
        printf 'SIEM_HOSTNAME=%s\n' "$HOSTNAME_OVERRIDE"
    fi
    if [ "$ROLE" = "firewall" ]; then
        printf 'FIREWALL_TYPE=%s\n' "${FW_TYPE:-generic}"
        if [ -n "$FW_LOG" ]; then
            printf 'FIREWALL_LOG_PATH=%s\n' "$FW_LOG"
        fi
    fi
    if [ "$ROLE" = "pihole" ]; then
        printf 'SIEM_PIHOLE_DB_PATH=%s\n' "${PIHOLE_DB:-/etc/pihole/pihole-FTL.db}"
    fi
} > "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"

AFTER="network-online.target"
if [ "$ROLE" = "pihole" ]; then
    AFTER="network-online.target pihole-FTL.service"
fi

cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Heimdall Agent (${ROLE})
After=${AFTER}
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${CONFIG_FILE}
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python -u ${INSTALL_DIR}/${AGENT_SCRIPT}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

if [ -n "$HOSTNAME_OVERRIDE" ]; then
    REPORT_HOST="$HOSTNAME_OVERRIDE"
else
    REPORT_HOST=$(hostname)
fi

HEALTH=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "$API_URL/health" || true)
if [ "$HEALTH" != "200" ]; then
    echo "Hub health check failed (HTTP ${HEALTH:-none}) at $API_URL/health" >&2
    echo "The service is installed. Logs: journalctl -u $SERVICE_NAME -f" >&2
    exit 1
fi

HEARTBEAT=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "$API_URL/heartbeat" \
    -H "api-key: $API_KEY" \
    -H "source-host: $REPORT_HOST" \
    -H "os-type: $OS_TYPE" \
    -H "source-site: $SITE_NAME" || true)
if [ "$HEARTBEAT" != "200" ]; then
    echo "Hub rejected the check-in (HTTP ${HEARTBEAT:-none}). Confirm the API key." >&2
    echo "Logs: journalctl -u $SERVICE_NAME -f" >&2
    exit 1
fi

echo "Heimdall is running as $REPORT_HOST ($OS_TYPE) in site $SITE_NAME."
echo "Service: systemctl status $SERVICE_NAME"
echo "Logs:    journalctl -u $SERVICE_NAME -f"
echo "Config:  $CONFIG_FILE"
echo "Remove:  curl -fsSL $API_URL/install/linux | sudo bash -s -- --uninstall"
