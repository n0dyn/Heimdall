# UniFi and other syslog devices

Heimdall listens for UDP syslog on port **5514** and stores normalized events through `/ingest`. The collector does not send Telegram messages itself. An event pages Telegram only when its severity is at least the existing threshold (4 by default).

## Point UniFi at Heimdall

Use the console SIEM export, not the UniFi Network API. IPS events are not available from the current local API.

1. Settings → Control Plane → Integrations → Activity Logging → **SIEM Server**.
2. Server `YOUR_HUB_IP`, port `5514`.
3. Settings → CyberSecure → Traffic Logging → the same server.
4. Enable Security Detections, Admin Activity, Critical, VPN, and Triggers.
5. Leave client activity and debug off. Leave per-policy firewall flow syslog off until you want that volume.
6. Repeat for each UniFi site.

On Network 8.x the same setting is Settings → System → Remote Logging. CEF export needs Network 8.5 or newer. Older consoles send plain syslog; gateway block lines are still stored as `CONNECTION_BLOCKED` at severity 2.

Devices often send the packets themselves. Allow UDP 5514 from the gateway, access points, and switches to the Heimdall host, not only from the controller address.

## What gets stored

| UniFi event | Heimdall type | Severity | Telegram at threshold 4 |
| --- | --- | --- | --- |
| IPS/IDS threat | `IDS_ALERT` | 4 (5 if CEF severity is 9 or 10) | Yes |
| Honeypot | `HONEYPOT` | 4 | Yes |
| Firewall block | `CONNECTION_BLOCKED` | 2 | No |
| Admin login or config change | `ADMIN_ACTION` | 3 | No |
| VPN authentication failure | `LOGIN_FAIL` | 4 | Yes |
| VPN session open or close | `VPN_SESSION` | 2 | No |
| Device offline or WAN failover | `DEVICE_OFFLINE` | 4 | Yes |
| Wi-Fi client connect, roam, disconnect | dropped |  | No |

`os_type` is `UNIFI`. Search with `os:UNIFI`.

Client events stay dropped unless `UNIFI_INGEST_CLIENTS=true`. Lines that are neither CEF nor a firewall block are dropped unless `SYSLOG_STORE_UNKNOWN=true` (those are severity 1).

Syslog ingest does not record a heartbeat for a UniFi gateway, access point, or switch. A silent device does not trip the host-down alert. Device offline arrives as its own event.

## Check that it works

```bash
nc -u -w1 YOUR_HUB_IP 5514 <<'EOF'
CEF:0|Ubiquiti|UniFi Network|9.4.19|201|Threat Detected and Blocked|7|proto=TCP src=203.0.113.10 dst=10.0.0.5 spt=52331 dpt=443 UNIFIcategory=Security UNIFIsubCategory=Threat UNIFIhost=gateway UNIFIthreatType=Test
EOF
```

That sample is CEF severity 7, which Heimdall stores as `IDS_ALERT` severity 4, so it will send the existing critical-event Telegram message. For a silent check, send a firewall block (CEF severity 3 or lower, Heimdall severity 2) instead. A Wi-Fi disconnect line should not be stored.

Other syslog senders (OPNsense, pfSense, a gateway netfilter line with `SRC=` and `DST=`) can use the same port. Block lines are stored. Unrecognized lines are ignored unless `SYSLOG_STORE_UNKNOWN` is on.
