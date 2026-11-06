# Heimdall vs Netdata: Consulting-Ready Alignment Plan

**Status:** analysis only — no collectors, schema, dashboard, or multi-tenant code in this document’s scope.
**Audience:** Heimdall as an MSP / consulting product (monitor client infrastructure, keep SIEM as a first-class capability).
**External source:** [netdata/netdata](https://github.com/netdata/netdata) and [Netdata Learn](https://learn.netdata.cloud) (Agent / Parent / Cloud; collect → store → query → alert).
**License constraint:** Netdata Agent is GPLv3+. This plan is feature-set inspiration only. Do not copy Netdata source, dashboards, or health configs.

---

## 1. What Heimdall is today

Heimdall is a **Mini-SIEM with a thin last-write-wins host snapshot (“RMM”) overlay**. It is not an observability product. Agents normalize security logs into `LogEvent`, POST them to a central FastAPI hub, and the LCARS dashboard charts **events**. A separate snapshot path overwrites one row per host with the latest CPU/RAM/disk/process numbers. That snapshot is **not** a queryable time-series of metrics.

### 1.1 Security-event ingest and query (first-class, shipped)

| Surface | Evidence |
|---|---|
| Unified event schema | `core/models.py` `LogEvent`: `event_id`, `timestamp`, `source_host`, `os_type`, `event_type`, `severity` (1–5), `source_ip`, `user`, `raw_message`. Event types are SIEM-shaped (`LOGIN_FAIL`, `SUDO_ESCALATION`, `DNS_BLOCK`, `CONNECTION_BLOCKED`, …). |
| Ingest | `core/server_api.py` `POST /ingest` — API-key gate, batch insert, implicit heartbeat on success. |
| Query | `core/server_api.py` `GET /events` — filters (`source_host`, `user`, `event_type`, `severity_min`, date range, …) plus `offset`/`limit` and `total_count`. |
| Store | `core/database_pg.py` `logs` table, `event_id TEXT UNIQUE`, indexes on timestamp / event_type / source_ip / os_type / severity. |
| Analytics named “metrics” | `GET /metrics` + `get_events_per_minute()` count **log events** per minute by OS — not CPU, RAM, or disk samples. `MetricsResponse` is `total_alerts_24h`, `threats_by_os`, `most_blocked_domain`, `top_attacking_ips`. |

Agents: `agents/agent_linux.py`, `agent_windows.py`, `agent_macos.py`, `agent_firewall.py`, `agent_pihole.py` parse logs / APIs and POST `LogEvent` batches. This pipeline stays.

### 1.2 Host heartbeats (presence, not telemetry)

| Surface | Evidence |
|---|---|
| Record | `POST /heartbeat` (`core/server_api.py`) and `record_heartbeat()` (`core/database_pg.py`): `heartbeats.source_host TEXT UNIQUE`, `ON CONFLICT … DO UPDATE SET last_seen`. |
| List | `GET /hosts` → `get_host_status(inactive_threshold_minutes=15)` splits active vs inactive. |
| Agents | Linux/Windows/macOS/Pi-hole send a heartbeat when the poll loop has no new events (`agent_linux.py` `run()`, default `interval=30`). |

Heartbeats answer “is the agent alive?” They do not store CPU, RAM, or disk history.

### 1.3 Latest-snapshot system status (the current “RMM”)

This is last-write-wins. It is **not** a queryable time-series of metrics.

| Surface | Evidence |
|---|---|
| Schema | `core/models.py` `SystemStatus`: one snapshot (`cpu_usage`, `cpu_count`, `memory_*`, `disk_info`, `network_info`, `top_processes`, `boot_time`, `timestamp`). Docstring: “Used for the RMM (Remote Monitoring) features.” |
| Storage | `core/database_pg.py` `system_status.source_host TEXT UNIQUE NOT NULL`. `upsert_system_status()` is `INSERT … ON CONFLICT (source_host) DO UPDATE` — each POST **replaces** the previous row. `get_system_status(host)` is `SELECT * FROM system_status WHERE source_host = %s` (latest only). The model’s `timestamp` is not even persisted; the row uses `last_updated`. |
| API | `POST /system-status` upserts; `GET /system-status/{hostname}` returns that one row or 404. There is no `from`/`to`/`step` query. |
| Collection | `agents/agent_linux.py` and `agents/agent_windows.py` `collect_system_status()` via **psutil** (CPU percent, RAM, disk partitions, interface IPs, top-10 processes, boot time), then `send_system_status()` every agent loop (30s). **macOS, firewall, and Pi-hole agents do not collect psutil snapshots.** |

Consequence: you can see “host X is at 73% CPU **now**.” You cannot answer “was CPU high for 40 minutes last Tuesday?” or graph RAM over a shift. Previous samples are discarded.

### 1.4 Event-centric dashboard (charts of logs, bars of snapshots)

`ui/index.html` (LCARS):

- **Event charts:** “EVENT TIMELINE - 24 HOURS”, “EVENT TYPES DISTRIBUTION”, “SEVERITY DISTRIBUTION” (`updateMainChart` / `updateTypesChart` / `updateSeverityChart`). The timeline prefers `metrics.events_per_minute` (log counts) and falls back to client-side event buckets.
- **Host list:** active/inactive counts from `GET /hosts`.
- **Snapshot bars (not time-series):** `showHostDetails()` fetches `GET /system-status/{hostname}` once; `updateHostModalWithRMM()` draws **progress bars** for current CPU/RAM/disk and a top-process table. No Chart.js series of CPU/RAM over time.

The dashboard is a SIEM console with a host-detail overlay, not a metric explorer.

### 1.5 Telegram and host-down alerting only

| Surface | Evidence |
|---|---|
| Loop | `core/alert_manager.py` `AlertManager.run()`: `check_critical_events()` (severity ≥ configurable threshold, default 4) and `check_inactive_hosts()` (heartbeat older than N minutes, default 15). Quiet hours suppress both. |
| Channel | `core/telegram_alerts.py` `send_critical_event_alert` / `send_host_down_alert` → one `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`. |
| Config | `GET/POST /alert-config*` — severity threshold, inactive minutes, quiet hours, enable flag. No CPU/RAM/disk rules. |

There are **no** resource-threshold alerts (CPU 90% for 5 minutes, disk 90%, memory pressure). If a client disk fills slowly, Heimdall is silent until the host stops heartbeating or a log event fires.

### 1.6 Tenancy, auth, and deploy shape (consulting gap)

- **One shared API key:** `VALID_API_KEYS = {SIEM_API_KEY}` in `core/server_api.py`. Dashboard hardcodes `window.API_CONFIG.api_key` in `ui/index.html`.
- **One global host namespace:** `heartbeats` / `system_status` / `logs` have no `client_id` / `site_id`. Two clients named `web-01` collide.
- **One Telegram chat** for every critical event and every host-down, all clients mixed.
- **One hub:** `docker-compose.yml` is a single `heimdall` API+dashboard plus Postgres. No per-client rooms, RBAC, or data isolation.

That is workable for a homelab or a single estate. It is not an MSP product.

### 1.7 Snapshot vs time-series (the category line)

| | Heimdall host “RMM” today | Time-series monitoring (Netdata analog) |
|---|---|---|
| Write | Upsert one row per host | Append samples on an interval |
| Read | Latest snapshot only | Range query: host + metric + `[from, to]` + step |
| Dashboard | Progress bars of “now” | Charts you zoom and overlay |
| Alerts | Host gone / SIEM severity | Thresholds and duration on the series |
| History | Discarded on the next POST | Retained (with optional downsampling) |

**Heimdall’s host RMM is last-write-wins snapshots, not a queryable time-series of metrics.** SIEM events *are* an append-only time-series — of security logs, not of system resources.

---

## 2. What Netdata actually is

Netdata is a **distributed, high-resolution observability pipeline**, not a SIEM. From the [GitHub README](https://github.com/netdata/netdata) and [Enterprise Evaluation Guide](https://learn.netdata.cloud/docs/welcome-to-netdata/enterprise-evaluation-guide):

**Components**

1. **Agent** — per node: collect, store, ML, health, local dashboard/API (GPLv3+). Per-second collection by default.
2. **Parent** — same binary, configured as a centralization point: children stream metrics; parent stores, queries, and evaluates health for the fleet.
3. **Cloud** — optional control plane (SaaS or on-prem): spaces/rooms, RBAC, SSO, federated multi-parent view. Metrics stay on Agents/Parents; Cloud does not become the metric database.

**Pipeline (per Agent):** Collect → Store (tiered dbengine) → Learn/Detect (per-metric unsupervised ML) → Check (health templates) → Stream → Query → Score. Dashboards are auto-generated from the metric metadata (NIDL), not hand-built Grafana boards.

**Defining mechanics used for the mapping below**

1. Distributed per-node collection of system/application metrics.
2. High-resolution time-series store and time-window query.
3. Auto-generated real-time metric dashboards.
4. Templated health alerts on those metrics.
5. Multi-node aggregated view (Parent / Cloud spaces and rooms).

Netdata also ships 800+ collectors, C dbengine (~0.5–0.6 bytes/sample, 1s / 1m / 1h tiers), unsupervised ML per metric, eBPF, SNMP, Kubernetes, and a 1-second C agent. Those are **polish / scale**, not the minimum to be recognizably “that monitoring product” for consulting. See [§5 Deferred](#5-explicitly-deferred-netdata-polish).

**Category mismatch:** cloning Netdata in Python on a SIEM hub is the wrong goal. The consulting product is **SIEM events + honest host time-series (seconds to tens of seconds) + client isolation**, not per-second C-agent parity.

---

## 3. Mapping: five Netdata mechanics → Heimdall

| # | Netdata mechanic | In Heimdall | Evidence (one line) |
|---|---|---|---|
| 1 | Distributed per-node collection of **system/application metrics** | **Partial** | Linux/Windows agents collect a **psutil snapshot** (CPU/RAM/disk/process) every 30s (`agent_linux.py` / `agent_windows.py` `collect_system_status`); macOS/firewall/Pi-hole do not; there are **no application collectors** (nginx, postgres, …). |
| 2 | High-resolution **time-series store** and **time-window query** | **Absent** | `system_status.source_host UNIQUE` + `upsert_system_status` last-write-wins; `GET /system-status/{hostname}` returns one row; no `[from,to]` metric API. (`logs` *is* time-series, but of SIEM events, via `GET /events`.) |
| 3 | Auto-generated **real-time metric dashboards** | **Partial** | `ui/index.html` auto-draws **event** charts (`events_per_minute`, type/severity) and **snapshot bars** in the host modal; it does not generate CPU/RAM/disk **time-series** charts or a fleet metric view. |
| 4 | **Templated health alerts** on those metrics | **Absent** | `alert_manager.py` only fires **SIEM severity** and **host-down** (stale heartbeat) to Telegram; no `template:` / `on: system.cpu` (or equivalent) resource rules, hysteresis, or duration. |
| 5 | **Multi-node aggregated view** | **Partial** | `GET /hosts` lists every heartbeat in **one global pool**; the dashboard sums active/inactive and mixes all hosts. No per-client/site rooms, no aggregated CPU/RAM across a node group, no Parent-style centralization of metric history. |

**Present:** none of the five as Netdata defines them. Closest shipped analog is (1) and (3) and (5) in snapshot/SIEM form.

### Optional extras (not gating)

| Topic | Netdata | Heimdall |
|---|---|---|
| Notification channels | Email, Slack, Teams, PagerDuty, Discord, Telegram, webhooks, … | Telegram only (`TELEGRAM_CHAT_ID` global). |
| SNMP / NetFlow / eBPF / k8s | First-class collectors | Absent (defer). |
| Containers | cgroup collectors | Absent (defer unless a client estate is container-heavy). |
| Logs as observability | systemd-journal / Windows Event Log **as metrics+logs** | Heimdall already treats Windows/Linux/macOS logs as **SIEM events** — keep that; do not replace it with Netdata-style journal browsing. |
| Auth | Cloud SSO / RBAC / spaces | Single API key. |

---

## 4. Product thesis for consulting

**Keep Heimdall’s identity:** Mini-SIEM + LCARS dashboard + Python agents you can drop on a client Windows/Linux box.

**Add the minimum Netdata-like layer so the same install is also “are the machines healthy?”**

That minimum is:

1. **Time-series host metrics** (append samples; query a window).
2. **Metric dashboards** (host + site charts of CPU/RAM/disk/network, plus a fleet strip).
3. **Resource-threshold alerts** (on those series), alongside existing SIEM + host-down Telegram alerts.
4. **Multi-client / site isolation** so consulting work does not dump every customer into one key, one host list, and one chat.

**Honest resolution:** 10–30 seconds is the analog (the Linux agent already loops at 30s). Per-second C collection is deferred. That is enough for MSP SLAs: disk filling, memory leak over hours, CPU pegged, host gone. It is not enough to replace Netdata for kernel-level troubleshooting — and it does not need to.

**Do not:** rewrite agents in C, discard `LogEvent`, clone Netdata UI, or build a billed “Heimdall Cloud.”

---

## 5. Explicitly deferred Netdata polish

These are **out of scope** for alignment. They are what would be required to *be* Netdata; they are not required to be a recognizably Netdata-like **monitoring companion** to Heimdall’s SIEM.

- **800+ collectors** (apps, cloud, SNMP, sensors, StatsD, OpenMetrics zoo).
- **C dbengine** (custom time-series engine, ~0.5 bytes/sample, 17-minute flush, tiered 1s/1m/1h files).
- **Unsupervised per-metric ML** (train at the edge, anomaly bit on every chart).
- **Netdata Cloud** (SaaS/on-prem control plane, claiming, spaces as a hosted product).
- **1-second C-agent rewrite** of Heimdall collectors.

Also deferred (same rationale): eBPF, NetFlow, Kubernetes collectors, copying GPLv3 Netdata code or dashboards, a billing/invoicing SaaS.

---

## 6. Phased alignment plan

SIEM ingest/query (`/ingest`, `/events`, `LogEvent`, log agents) remains first-class in every phase. New work is additive.

### Phase 1 — Time-series host metrics (foundation)

**Goal:** stop throwing samples away. Same psutil fields, stored as history, queryable by window.

**Keep:** `LogEvent` path, heartbeats, and a **latest snapshot** (current host modal “now” view can keep reading a latest row or `ORDER BY time DESC LIMIT 1`).

**Add:**

- Append-only metric store in Postgres (already the hub DB in `database_pg.py` / `docker-compose.yml`). Suggested shape: `(time, source_host, client_id, site_id, metric, value, labels jsonb)` with a BRIN/btree on `(source_host, metric, time)`. `client_id` / `site_id` columns now, even if UI isolation is Phase 3 — avoids a second migration.
- Agent change: Linux/Windows `send_system_status` **also** POSTs a sample batch (CPU%, RAM%, per-mount disk%, maybe 1-minute network counters). Keep the 30s loop; optionally 10–15s later. Extend macOS with the same psutil (or equivalent) snapshot so RMM is not Windows/Linux-only.
- API: `POST /metrics/samples` (or extend `/system-status` to append) and `GET /metrics/query?host=&metric=&from=&to=&step=`. Downsample in SQL (`date_bin`) for wide windows.
- Retention: start with 7–14 days at native step, 90 days at 5-minute rollup. Not dbengine; Postgres is enough at MSP scale (tens to low hundreds of hosts × ~20 series × 2 samples/min).

**Done when:** a curl of `/metrics/query` for one host returns more than one CPU point across an hour; the old latest snapshot still works.

### Phase 2 — Metric dashboards

**Goal:** the dashboard looks like monitoring, not only a SIEM, without abandoning LCARS.

**Add:**

- Host detail: Chart.js time-series for CPU, RAM, disk (per mount), optional network — sourced from `/metrics/query`, not from a single snapshot bar. Keep snapshot bars as the “now” header.
- Fleet / site strip: one row per host with sparklines or last-value + 1h trend; click through to host detail.
- New top-level **Metrics** (or **Infrastructure**) view next to the event timeline. Event charts stay on the SIEM home.
- Time window control (1h / 6h / 24h / 7d) shared by host and fleet charts.

**Done when:** an operator can open a host and see CPU/RAM **over the last 24 hours**, and see all hosts in a site on one page.

Do not auto-generate hundreds of charts from 800 collectors. Hand-build the small set operators actually use (system resources + process table + SIEM events on the same host). That is “recognizably that product” for consulting; NIDL-scale autogen is deferred.

### Phase 3 — Resource-threshold alerts + multi-client / site isolation

**3a. Resource alerts (on the new series)**

Extend `AlertManager` (do not replace SIEM/host-down):

| Rule (templates, not ML) | Default |
|---|---|
| CPU high | `cpu_usage > 90` for 10 minutes |
| Memory high | `memory_percent > 90` for 10 minutes |
| Disk high | any mount `percent > 90` (warning 80) |
| Host down | keep existing heartbeat stale check |

Each rule: name, metric selector, threshold, duration, severity, hysteresis (clear at threshold − 5%). Persist in `config` or a small `alert_rules` table. Dedup with `alert_history` the same way SIEM alerts do.

Route: still Telegram in v1 of this phase; add Slack/email later (not required to match Netdata’s channel list).

**3b. Client / site isolation (MSP must-have)**

Without this, time-series and dashboards make the mixing problem worse.

| Piece | Behavior |
|---|---|
| Tenant model | `clients` (consulting customer) and `sites` (office / DC / “prod”). Hosts belong to one site. |
| Auth | Per-client ingest API keys (and a hub operator key). Agents get `SIEM_API_KEY` that can only write that client’s hosts. Dashboard sessions scoped to client(s). **Stop shipping one global key in `ui/index.html`.** |
| Query isolation | Every `logs` / `heartbeats` / `system_status` / metric query filters `client_id`. Two clients may both have `web-01`. |
| Alert routing | Per-client Telegram chat (or Slack webhook). A disk alert for Client A must not land in Client B’s channel or a shared dump. |
| UI | Client switcher + site rooms (Netdata “spaces/rooms” analog, implemented in Heimdall, not Cloud). Operator sees all; a client portal later can see only theirs. |

**Done when:** two clients can run agents against one hub without seeing each other’s events, metrics, or alerts; resource alerts fire on CPU/disk independently of SIEM severity.

### Suggested order vs consulting revenue

Phase 1 is blocking. Phase 3b (isolation) can overlap Phase 2: schema keys in Phase 1, enforcement + UI rooms in Phase 3. Do not build Cloud, billing, or a public multi-tenant SaaS.

### Out of these phases (reminder)

SIEM event types, log agents, LCARS visual identity, and Telegram for **security** events stay. Application collectors, ML, 1s C rewrite, and Netdata Cloud stay in [§5](#5-explicitly-deferred-netdata-polish).

---

## 7. Consulting operating model (how you would actually sell this)

1. **Hub in your DC or a small VPS you control** (`docker-compose.yml` already: API :8010, dashboard :8501, Postgres). HTTPS in front; rotate the operator key.
2. **One agent per client machine** (existing Linux script / Windows service EXE). Env: hub URL, **client-scoped** API key, hostname. Same binary for SIEM + metrics after Phase 1.
3. **Per-client room** in the dashboard: events + infra charts + alert routing to that client’s Telegram (and yours).
4. **SLAs you can honestly offer after Phases 1–3:** host down (~15 min today; can tighten), disk/CPU/RAM thresholds, security events (failed logins, sudo, firewall blocks, DNS blocks). You cannot honestly offer “per-second, 800 integrations, ML anomalies” — do not put that on a statement of work.
5. **When a client needs Netdata itself:** install Netdata **beside** Heimdall for deep node troubleshooting; Heimdall remains the SIEM + MSP roll-up. Alignment is not “forbid Netdata.”

---

## 8. Risks

- **Calling snapshot RMM “metrics”** in marketing or UI will be false until Phase 1 ships history. Keep the snapshot-vs-time-series language internally.
- **GPLv3:** implementing collectors by reading Netdata plugins is a license/copyright problem. Re-implement with psutil / OS APIs / documented public interfaces.
- **Postgres as TSDB** will hurt if someone aims at thousands of hosts at 1s. The plan’s scale is consulting estates at 10–30s. If that changes, export to a real TSDB — still not a C dbengine rewrite.
- **Hostname collisions** exist today (`UNIQUE source_host`). Isolation must key hosts as `(client_id, source_host)`.
- **Single Telegram chat** will page you for every client at once until 3b.

---

## 9. Summary

Heimdall today: **SIEM event pipeline (complete) + heartbeats + last-write-wins psutil snapshots + event dashboard + Telegram for critical events and host-down.** Host RMM is not time-series.

Netdata: **per-node metric collection, time-series store/query, auto metric dashboards, templated health, multi-node aggregation.** In Heimdall those five are absent or only partial (snapshot/SIEM stand-ins).

Alignment for consulting: **keep SIEM; add time-series metrics, metric dashboards, resource alerts, and client/site isolation in three phases; defer 800+ collectors, C dbengine, per-metric ML, Netdata Cloud, and a 1-second C agent.**
