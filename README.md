<div align="center">

# 🛡️ SentinelPi

### Turn a spare Raspberry Pi into an always-on guardian for your whole network.

> *It learns what "normal" looks like — then tells you, in plain English, the moment something doesn't fit.*

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20%7C%20Linux-C51A4A?logo=raspberrypi&logoColor=white)](#-requirements)
[![Release](https://img.shields.io/badge/release-v1.0.0-success.svg)](https://github.com/sparktron/sentinelPi/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/sparktron/sentinelPi/actions/workflows/ci.yml/badge.svg)](https://github.com/sparktron/sentinelPi/actions/workflows/ci.yml)
[![Defensive only](https://img.shields.io/badge/scope-defensive%20only-blue.svg)](#-safety-boundaries)

<img src="docs/images/dashboard-hero.png" alt="SentinelPi dashboard — summary cards and recent alerts" width="900">

</div>

---

> **🔒 Defensive by design.** SentinelPi only *watches*. No exploit code, no traffic injection, no
> credential harvesting, no MITM. Its optional active-response layer is opt-in, dry-run by default,
> and human-approval gated. See [Safety boundaries](#-safety-boundaries).

## What is it?

Most home and small-office networks are completely unmonitored — you'd never know a smart bulb
started beaconing to a C2 server or a new device quietly joined your LAN. **SentinelPi** is a
lightweight sensor that fixes that.

Point it at your network and it spends a few days learning the rhythm of your traffic — who talks
to whom, when, and how much. After that, it flags the things that break the pattern: rogue devices,
ARP spoofing, port scans, malware beaconing, DNS abuse, lateral movement, SSH brute force, and more.
Every alert arrives with a **plain-English description, a confidence score, and a recommended next
step** — not a wall of packets.

It runs for months on a Pi, works **without root**, stays **quiet** (no alert floods), and can even
**act** on the worst threats once you trust it to.

Current development follow-ups from the latest code review are tracked in
[docs/DEVELOPMENT_ROADMAP.md](docs/DEVELOPMENT_ROADMAP.md).

## ✨ Highlights

|  |  |
|---|---|
| 🧠 **Learns your network** | Welford online statistics build a per-host behavioral baseline — deviations are *scored*, not hard-coded. No tuning required to start. |
| 🔍 **Catches the real stuff** | ARP spoofing, port scans, C2 beaconing, DNS tunneling/DGA, encrypted-DNS bypass, lateral movement, SSH brute force, new-country connections. |
| 🌐 **Sees the whole network** | Multi-sensor mesh over mTLS, NetFlow/conntrack/firewall flow ingest, and SPAN/mirror-port mode — not just the Pi's own host. |
| 🛰️ **Enriches every alert** | Threat-intel blocklists, passive device fingerprinting, GeoIP + ASN context attached automatically. |
| 🖥️ **Sleek live dashboard** | Dark-themed web UI with SSE live updates, device inventory, per-host drill-downs, suspicion trends, and a response approval queue. |
| 🛡️ **Can fight back (safely)** | Optional firewall block / DNS sinkhole / ARP re-pin / kill-switch — off by default, dry-run first, human-approved. |
| 📣 **Tells you anywhere** | Email, ntfy push (with Approve/Reject buttons), Twilio SMS, webhooks, plus SIEM export (syslog ECS/CEF) and OpenTelemetry. |
| 🩺 **Watches itself** | A built-in watchdog raises `SYSTEM` alerts when *SentinelPi* is degraded — dead threads, stale capture, low disk. |

## 🚀 Quick start

Get monitoring in about five minutes. This installs SentinelPi as a hardened systemd service that
runs as its own locked-down user (never root) on a Raspberry Pi or any Debian-based Linux box.

```bash
git clone https://github.com/sparktron/sentinelPi.git
cd sentinelPi

# 1. Install as a systemd service (creates the sentinelpi user, venv, and CAP_NET_RAW grant)
sudo bash scripts/install.sh

# 2. Tell it about your network: interface, subnet, gateway, and your trusted devices
sudo nano /etc/sentinelpi/sentinelpi.yaml

# 3. Validate the config, then start watching
sudo -u sentinelpi /opt/sentinelpi/venv/bin/python -m sentinelpi.main --check-config
sudo systemctl start sentinelpi

# 4. Watch it work
sudo journalctl -u sentinelpi -f
```

The **three settings that matter most** are `network.interfaces`, `network.subnets`, and
`network.gateway_ip` — plus listing your known gear under `trusted_devices` so you aren't alerted
about your own phones and laptops. Everything else ships with a safe default.

**Open the dashboard** at **http://localhost:8888/**. Authentication is always on — set a stable
token under `dashboard.access_token`, or let SentinelPi print a random one to the log on first run.
Keep it on loopback and reach it over SSH:

```bash
ssh -L 8888:127.0.0.1:8888 pi@your-pi
# then browse to http://localhost:8888/ and paste your token
```

> 💡 **Just want to try it?** Skip systemd entirely — `bash scripts/setup_venv.sh && source venv/bin/activate`,
> then `SENTINELPI_CONFIG=config/sentinelpi.yaml python -m sentinelpi.main`. Add `sudo` only if you
> turn on packet capture; `/proc`-only mode needs no privileges at all.

> 🐳 **Prefer Docker?** `docker compose up -d --build` — see [Deployment](#-deployment).

## 📸 See it

<table>
  <tr>
    <td align="center" width="50%"><b>Live dashboard</b><br><sub>summary cards · recent alerts · SSE live feed</sub></td>
    <td align="center" width="50%"><b>Device inventory</b><br><sub>every host, classified, ranked by suspicion</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/dashboard.png" alt="Full SentinelPi dashboard"></td>
    <td><img src="docs/images/device-inventory.png" alt="Device inventory and most-suspicious hosts"></td>
  </tr>
  <tr>
    <td align="center"><b>Active-response approval queue</b><br><sub>approve or reject pending actions with one click</sub></td>
    <td align="center"><b>Token login</b><br><sub>signed, HttpOnly session cookie</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/active-response.png" alt="Active response approval queue"></td>
    <td align="center"><img src="docs/images/login.png" alt="SentinelPi dashboard login" width="360"></td>
  </tr>
</table>

## 🧭 How it works

```
   ┌──────────────────────────────┐
   │  INPUTS                       │   scapy capture (optional, needs CAP_NET_RAW)
   │  packets · /proc · flows ·    │   /proc/net polling (no root)
   │  auth log                     │   conntrack / NetFlow / IPFIX / filterlog
   └──────────────┬───────────────┘
                  │ events
   ┌──────────────▼───────────────┐
   │  DETECTORS + BASELINE         │   ARP · Port Scan · Beacon · Connection
   │  learn normal, score deviation│   DNS · DoH · Lateral · Auth · Geo/ASN
   │  + THREAT INTEL enrichment    │   Threat-intel · Host-profile · Active-hours
   └──────────────┬───────────────┘
                  │ alerts
   ┌──────────────▼───────────────┐
   │  ALERT MANAGER                │   dedup · cooldown · correlation · enrichment
   └───┬──────┬──────┬──────┬──────┘
       │      │      │      │
   ┌───▼──┐┌──▼───┐┌─▼────┐┌▼──────────┐
   │ UI/  ││SQLite││Notify││ Responder │  ← every stage opt-in & gated
   │ SSE  ││  DB  ││ +SIEM││  Manager  │
   └──────┘└──────┘└──────┘└───────────┘
```

1. **Inputs** feed a unified event stream — use as many or as few as you like.
2. **Detectors** compare each event against a learned baseline and rules; threat-intel, GeoIP, and ASN
   data enrich the result.
3. The **Alert Manager** deduplicates, applies cooldowns, correlates related events into *incidents*,
   and routes everything to your outputs.
4. Optionally, the **Responder Manager** contains a confirmed threat — only when you've explicitly armed it.

---

# 🔬 Deep dive (for power users)

Everything above gets you running. Below is the full reference — expand what you need.

<details>
<summary><b>🔍 Full detection catalog</b></summary>

<br>

| Detector | What it finds | Method |
|----------|---------------|--------|
| **ARP** | Gateway MAC changes, ARP conflicts, reply floods (MITM signature) | Rule-based |
| **Port scan** | Vertical scans and subnet sweeps | Sliding-window counters |
| **Beacon** | Regular outbound intervals (malware C2) | Coefficient of variation |
| **Connection** | Count spikes, new destinations, new listening ports | Baseline z-score |
| **DNS** | DGA domains, DNS tunneling, NXDOMAIN floods | Entropy + rate analysis |
| **DoH / DoT** | Clients bypassing local DNS via encrypted resolvers | Port + resolver match |
| **Lateral movement** | Admin-protocol fan-out between internal hosts | Rule + baseline |
| **Auth log** | SSH brute force, new logins, sudo abuse | Pattern matching |
| **Threat intel** | Connections to known-bad IPs/domains | Blocklist match |
| **GeoIP / ASN** | First connection to a new country; bad-reputation networks | Per-host baseline |
| **Active hours** | Activity outside a host's learned schedule | Time-window baseline |
| **Host profile** | First use of an unfamiliar port, peer, protocol, or byte-range for a host | Per-host behavior baseline |

**Incident correlation** (optional) folds related alerts into a single `INCIDENT` with a timeline —
e.g. *new device → port scan → lateral movement*, or one actor seen across multiple sensors/targets.

**Intelligence & enrichment** layered on top:
- **Threat-intel feeds** — abuse.ch URLhaus / Feodo Tracker, Spamhaus DROP; cached locally and refreshed daily.
- **Passive device fingerprinting** — classifies cameras, phones, IoT, NAS, consoles, printers, routers… from OUI + hostname + DHCP.
- **GeoIP + ASN** — country and network/operator context attached to every external destination.
- **Alert explainability** — every alert carries a structured "why this fired" payload (which threshold, what baseline, how confidence was computed), rendered inline in the dashboard.

</details>

<details>
<summary><b>🛡️ Active response — the safety ladder</b></summary>

<br>

SentinelPi can *act* on the worst alerts, but it is built so it never surprises you. Responders only
ever **describe** an action; a single `ResponderManager` decides whether it actually runs, through a
layered safety ladder:

```
master off  (response.enabled: false)   →  nothing is planned           ← default
dry-run     (dry_run: true)              →  decide + log, never execute  ← default when enabled
armed       (require_approval: true)     →  hold as PENDING for human approval
trusted     (auto_execute_categories)    →  fire automatically for explicitly listed categories
```

Available responders (all off by default, each with its own guardrails):

| Responder | Action | Guardrails |
|-----------|--------|------------|
| **Firewall** | DROP a known-bad external IP (iptables/nftables) | Never blocks private/loopback/whitelisted IPs |
| **DNS sinkhole** | Block a malicious domain (hosts / Pi-hole / Unbound) | Never sinkholes a whitelisted domain |
| **ARP restore** | Re-pin the configured gateway MAC on poisoning | Requires `gateway_ip` **and** `gateway_mac` |
| **Kill switch** | Run an operator-supplied command on compromise | No command + no categories = never fires |

The honest workflow: watch decisions in **dry-run for days**, then **arm with approval** before
trusting any category to fire on its own. When armed, pending actions surface in the dashboard's
**Active Response** queue (and as Approve/Reject buttons in an ntfy push) for one-click decisions.

</details>

<details>
<summary><b>🌐 Whole-network coverage</b></summary>

<br>

Go beyond a single host:

- **Multi-sensor mesh.** Run SentinelPi on several segments and forward alerts to a central collector
  over **mutual-TLS** (shared-key auth layered with reverse-proxy-verified client certs). The
  collector runs every forwarded alert through the full pipeline, and the dashboard offers per-sensor views.
- **Cross-sensor correlation.** One actor crossing multiple sensors or hitting multiple targets is
  escalated into a single `INCIDENT` instead of N scattered alerts.
- **Router / firewall flow ingest.** Feed `conntrack`, **NetFlow v5/v9 / IPFIX**, and pfSense/OPNsense
  `filterlog` exports so SentinelPi analyzes flows it could never sniff directly — every connection
  detector works on them unchanged.
- **SPAN / mirror-port mode.** Plug the Pi into a switch mirror port and set `network.mirror_mode: true`
  to capture *all* subnet traffic in promiscuous mode, not just this host's.
- **DHCP-lease identity.** Name devices from your DHCP server's leases (dnsmasq / ISC) instead of guessing.

</details>

<details>
<summary><b>⚙️ Configuration reference</b></summary>

<br>

All behavior is driven by a single YAML file (`config/sentinelpi.yaml`). Every setting ships with a
safe default — you only configure what differs for your network.

| Section | What it controls |
|---------|------------------|
| `network` | Interfaces, subnets, gateway IP/MAC, SPAN/mirror mode |
| `trusted_devices` | Your known devices (suppresses new-device alerts) |
| `monitoring` | Sensitivity profile, packet capture on/off, watchdog/self-monitoring, per-feature toggles |
| `thresholds` | Per-detector tuning (scan windows, beacon intervals, z-score cutoffs, adaptive thresholds) |
| `whitelist_ips` / `whitelist_domains` / `whitelist_ports` | Never-alert allowlists |
| `dashboard` | Bind host/port and access token |
| `storage` | SQLite database path and retention |
| `logging` | Log level, rotation, JSON log path |
| `notifications` | Email, Twilio SMS, webhook, ntfy, SIEM (syslog ECS/CEF), OpenTelemetry (OTLP/HTTP) |
| `reporting` | Daily / weekly digest settings |
| `threat_intel` | Enable blocklist feeds and matching |
| `response` | Optional active-response layer (off + dry-run by default) |
| `cluster` | Sensor / collector role and mTLS forwarding |
| `correlation` | Cross-sensor and single-host incident correlation |
| `flow` | conntrack / NetFlow / IPFIX / filterlog ingestion |

**Sensitivity profiles** (`monitoring.sensitivity_profile`): `conservative`, `balanced`, or
`aggressive` — a one-word dial that sets sane defaults across every detector.

**Validate before you run:**
```bash
sentinelpi --check-config   # static validation: CIDRs, ports, severities, backends, profiles
sentinelpi --check          # also actively probes notifiers/responders in dry-run (no side effects)
```

Full reference: **[docs/configuration_guide.md](docs/configuration_guide.md)**.

</details>

<details>
<summary><b>📣 Notifications & integrations</b></summary>

<br>

Route alerts wherever you live:

- **Console + rotating JSON log + SQLite** — always on.
- **Email** — SMTP, timezone-aware timestamps.
- **ntfy push** — with **Approve/Reject action buttons** for pending responder actions, so you can
  authorize a block from your phone without opening the dashboard.
- **Twilio SMS** — high-signal alerts as text messages; Account SID/Auth Token or API Key auth.
- **Webhooks** — POST alerts to any endpoint.
- **SIEM export** — stream to a syslog collector as **ECS** (Elastic Common Schema JSON) or **CEF**
  (ArcSight) over UDP/TCP with RFC 5424 framing → feeds Wazuh, Splunk, Elastic.
- **OpenTelemetry** — POST alerts as **OTLP/HTTP** JSON logs to a collector's `/v1/logs` (no OTel SDK dependency).
- **Daily / weekly reports** — rolled-up digests including a health summary from the watchdog.

Every network channel participates in `sentinelpi --check`, which sends a clearly-labelled test alert
(or connects without sending, for email) so you can prove delivery before going live.

</details>

<details>
<summary><b>💻 CLI reference</b></summary>

<br>

```text
sentinelpi [--config PATH] [--check-config] [--check]
           [--backup PATH] [--restore PATH] [--force] [--version]

  -c, --config PATH   Path to the YAML config (or set SENTINELPI_CONFIG)
      --check-config  Validate configuration and exit (non-zero on any issue)
      --check         Validate config, then actively test configured outputs in dry-run
      --backup PATH   Write a database snapshot to PATH and exit (safe while running)
      --restore PATH  Restore a database snapshot from PATH and exit (stop the service first)
      --force         With --restore, allow a snapshot from a newer schema version
      --version       Print version and exit
```

**Backup & restore.** `--backup` writes one compressed, self-describing snapshot of the database —
which holds *all* learned baselines (known destinations, hourly stats, DNS domains, per-host
countries, active hours, behavioral profiles) plus alerts and devices. It uses SQLite's online
backup API, so it's point-in-time consistent and safe to run live (e.g. nightly cron to a USB stick).
`--restore` verifies the snapshot's checksum and SQLite integrity, moves the existing DB aside to
`<db>.pre-restore-<timestamp>`, and installs the snapshot — so a sensor's months of learned memory
survive an SD-card failure or a Pi re-image. Stop the service first. Older-schema snapshots migrate on
next startup; newer ones are refused unless you pass `--force`.

</details>

<details>
<summary><b>🚦 Alert severity levels</b></summary>

<br>

| Level | Meaning | Example |
|-------|---------|---------|
| `info` | Informational, no action needed | Client using encrypted DNS |
| `low` | Minor anomaly, worth noting | New device from a known vendor |
| `medium` | Suspicious, investigate when convenient | New SSH login from an unseen IP |
| `high` | Likely malicious, investigate promptly | Port scan; connection to known-bad IP |
| `critical` | Active threat indicator, act now | Gateway MAC changed (ARP poisoning) |

</details>

<details>
<summary><b>🏗️ Architecture & module map</b></summary>

<br>

| Module | Purpose |
|--------|---------|
| `capture/` | Packet sniffing (scapy), `/proc/net` polling, flow ingest, honeypot |
| `detectors/` | Rule-based and baseline-deviation anomaly detectors |
| `inventory/` | Device tracking, classification, DHCP-lease correlation |
| `baseline/` | Welford online statistics, behavioral baseline |
| `intel/` | Threat-feed download, caching, and matching |
| `alerts/` | Dedup, cooldown, correlation, notification routing |
| `responders/` | Optional, gated active-response actions |
| `storage/` | SQLite persistence (WAL mode, thread-safe, migrations) |
| `ui/` | Flask web dashboard + multi-sensor collector |
| `config/` | YAML loading and validation |
| `utils/` | Network helpers, GeoIP/ASN, timezone-aware clock |

**Built to run for months:** thread-safe, WAL-mode SQLite, bounded memory, clean systemd shutdown,
and a watchdog that raises `SYSTEM` alerts when SentinelPi itself degrades (dead worker threads,
stale capture, queue saturation, threat-feed refresh failures, low disk).

</details>

<details>
<summary><b>🧪 Testing & development</b></summary>

<br>

```bash
git clone https://github.com/sparktron/sentinelPi.git
cd sentinelPi
bash scripts/setup_venv.sh
source venv/bin/activate

# Test suite
python -m pytest tests/ -v

# Local CI checks
python -m compileall -q src tests
ruff check src tests

# Coverage (CI fails below the fail_under floor in pyproject.toml — currently 70%)
python -m pytest tests/ --cov=sentinelpi --cov-report=term-missing
```

Fixtures simulate real attack traffic so detectors are tested end-to-end: normal baseline traffic,
port scans (100+ ports in 30s), beaconing malware (regular 60s intervals), ARP spoofing (gateway MAC
change), SSH brute force (50 failures in 100s), DNS tunneling, and DGA NXDOMAIN floods.

CI runs on Python 3.11 + 3.12: compile checks, ruff, mypy, coverage, and a packaging smoke test that
builds and installs the wheel.

</details>

## 📦 Deployment

<details open>
<summary><b>Raspberry Pi / Debian (systemd)</b></summary>

<br>

The installer creates a locked-down `sentinelpi` system user, sets up a virtualenv under
`/opt/sentinelpi`, grants `CAP_NET_RAW` to the venv Python (so the daemon never runs as root), and
registers the systemd service. See [Quick start](#-quick-start) for the full flow.

```bash
sudo bash scripts/install.sh
# uninstall later (keeps config/data/logs; add --purge to remove them):
sudo bash scripts/uninstall.sh
```

</details>

<details>
<summary><b>Docker</b></summary>

<br>

A multi-stage [`Dockerfile`](Dockerfile) builds a slim image that runs as a non-root `sentinelpi`
user; [`docker-compose.yml`](docker-compose.yml) wires it up for LAN monitoring:

```bash
git clone https://github.com/sparktron/sentinelPi.git
cd sentinelPi
# Edit ./config/sentinelpi.yaml for your network first (it's mounted into the container)
docker compose up -d --build
docker compose logs -f
```

Compose uses **host networking** plus `NET_RAW`/`NET_ADMIN` so the container can capture LAN traffic
without root. The database and baselines persist in named volumes. For a capability-free,
`/proc`-only deployment, set `monitoring.packet_capture_enabled: false` and drop the `cap_add` block.
The image ships a `HEALTHCHECK` that runs `--check-config`.

</details>

## 📋 Requirements

- Raspberry Pi 4 or newer (or any Debian-based Linux host)
- Python **3.11+**
- A network interface on the subnet you want to watch
- Root or `CAP_NET_RAW` for packet capture — **optional**; `/proc` polling and flow ingest work
  without elevated privileges

## 📚 Documentation

- [Threat Model & Scope](docs/threat_model.md)
- [Configuration Guide](docs/configuration_guide.md)
- [systemd Setup Guide](docs/systemd_setup.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security Considerations](docs/security_considerations.md)
- [Feature Roadmap](docs/FEATURE_ROADMAP.md) · [Development Roadmap](docs/DEVELOPMENT_ROADMAP.md)

## 🔒 Safety boundaries

SentinelPi is a **defensive monitoring tool**. It does **not**:

- Inject, modify, or forge network traffic
- Perform active exploitation or vulnerability scanning
- Harvest credentials or intercept encrypted traffic
- Execute man-in-the-middle attacks
- Provide remote shell access or persistence mechanisms
- Include any offensive security capability

The optional [active-response](#%EF%B8%8F-active-response--the-safety-ladder) layer is **off and in
dry-run by default**, refuses to touch private/loopback/whitelisted targets, and holds risky actions
for explicit human approval. It exists to *contain* a confirmed threat (block a C2 IP, sinkhole a
malicious domain, re-pin your real gateway MAC) — never to attack.

## License

[MIT](LICENSE) © SentinelPi Project
