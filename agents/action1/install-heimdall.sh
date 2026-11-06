#!/bin/bash
# Heimdall installer for an Action1 Bash script.
# Action1 runs this as root on macOS and Linux.
# Bash scripts cannot take Action1 parameters, so fill api_url and api_key
# in the script for a single run. Do not save the API key in the Script Library.
#
# The hub button "Install Heimdall agent" does that fill-in per platform:
# macOS calls /install/macos, Linux calls /install/linux, and --role is Linux only.
#
# role is linux, firewall, or pihole. Leave hostname empty to keep the computer's name.

set -euo pipefail

api_url="${api_url:-}"
api_key="${api_key:-}"
hostname="${hostname:-}"
role="${role:-linux}"

if [ -z "$api_url" ] || [ -z "$api_key" ]; then
    echo "Set api_url and api_key in this script before Action1 runs it." >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin)
        route="macos"
        ;;
    Linux)
        route="linux"
        ;;
    *)
        echo "Heimdall's Action1 installer runs on macOS and Linux." >&2
        exit 1
        ;;
esac

args=(--url "$api_url" --key "$api_key")
if [ -n "$hostname" ]; then
    args+=(--hostname "$hostname")
fi
if [ "$route" = "linux" ]; then
    args+=(--role "$role")
fi
curl -fsSL "${api_url%/}/install/${route}" | bash -s -- "${args[@]}"
