# SentinelPi — Configuration Guide

## Config File Location

SentinelPi searches for configuration in this order:

1. `--config` command-line argument
2. `SENTINELPI_CONFIG` environment variable
3. `/etc/sentinelpi/sentinelpi.yaml`
4. `~/.config/sentinelpi/sentinelpi.yaml`
5. `config/sentinelpi.yaml` (relative to working directory)
6. `sentinelpi.yaml` (current directory)

If no file is found, built-in defaults are used.

## Essential Settings

### Network Configuration

```yaml
network:
  interfaces:
    - eth0            # Your monitoring interface
  subnets:
    - 192.168.1.0/24  # Your local network CIDR
  gateway_ip: "192.168.1.1"
  gateway_mac: "aa:bb:cc:dd:ee:ff"  # From: arp -n | grep 192.168.1.1
```

Find your interface: `ip link show`
Find your subnet: `ip addr show eth0`
Find your gateway: `ip route | grep default`
Find gateway MAC: `arp -n | grep <gateway_ip>`

### Trusted Devices

Trusted devices suppress new-device alerts:

```yaml
trusted_devices:
  - ip: "192.168.1.100"
    mac: "aa:bb:cc:dd:ee:ff"
    name: "Desktop PC"
  - mac: "dc:a6:32:xx:xx:xx"
    name: "Raspberry Pi"
```

### Sensitivity Profile

Controls overall alert aggressiveness:

| Profile | Port scan threshold | Connection spike | Beacon CV | SSH failures |
|---------|-------------------|-----------------|-----------|--------------|
| `conservative` | 30 ports/min | 5x baseline | 0.10 | 20 failures |
| `balanced` | 15 ports/min | 3x baseline | 0.15 | 10 failures |
| `aggressive` | 8 ports/min | 2x baseline | 0.20 | 5 failures |

```yaml
monitoring:
  sensitivity_profile: balanced
```

## Feature Toggles

```yaml
monitoring:
  packet_capture_enabled: true     # Requires root/CAP_NET_RAW
  dns_monitoring_enabled: true     # Needs packet capture
  auth_log_enabled: true           # Parses /var/log/auth.log
  file_integrity_enabled: false    # Optional config file hashing
  geo_enabled: false               # Requires GeoLite2 database
  active_discovery_enabled: false  # Low-rate ARP ping (off by default)
  active_hours_detection_enabled: true
  host_profile_detection_enabled: true
  self_monitoring_enabled: true    # SYSTEM alerts if SentinelPi itself degrades
```

`active_hours_detection_enabled` learns when each host is normally active.
`host_profile_detection_enabled` learns each host's usual destination ports,
internal peers, L4 protocols (tcp/udp/icmp), and per-flow transfer-size buckets,
then flags the first off-profile value once that dimension's profile is
established (`host_profile_min_known_ports`, `_peers`, `_protocols`,
`_byte_ranges`). Byte-range profiling needs a flow source that reports byte
counts (NetFlow); under SYN-only capture or conntrack it stays dormant.

`adaptive_thresholds_enabled` makes rate-based detectors (port scan, host sweep,
DNS NXDOMAIN/DGA rate, lateral-movement fanout) self-tune per host. A host that
keeps tripping the same signal is treated as chronically noisy: its effective
threshold is scaled up (by `adaptive_threshold_step` per extra trip beyond
`adaptive_threshold_trips_before_backoff`, capped at
`adaptive_threshold_max_multiplier`) so it must clear a higher bar. Trips age out
of `adaptive_threshold_window_seconds`, so the bar decays back once the host goes
quiet. The bar is never lowered below the global threshold, so quiet hosts keep
full sensitivity — this lets a noisy network settle without you dulling
sensitivity for everyone. When an adaptive bar is in effect, the alert's "Why
this fired" explanation shows the raised threshold and its base value.

### Self-Monitoring Watchdog

The watchdog raises `SYSTEM` alerts when SentinelPi's own runtime health degrades:
managed worker threads stop, packet/flow events stop arriving while event sources
are active, threat-intel refresh fails or goes stale, the capture queue approaches
capacity, or the database volume falls below the configured free-space floor. The
latest snapshot is also returned from `/api/status`.

```yaml
monitoring:
  self_monitoring_enabled: true
  self_monitoring_interval_seconds: 60
  self_monitoring_queue_warn_ratio: 0.80
  self_monitoring_disk_free_min_mb: 512
  self_monitoring_capture_stale_seconds: 300
  self_monitoring_threat_intel_stale_multiplier: 2.0
```

## Dashboard

```yaml
dashboard:
  enabled: true
  host: "127.0.0.1"    # ONLY change to "0.0.0.0" if you understand the security implications
  port: 8888
  access_token: ""      # Stable token; if left blank, one is generated and logged each run
```

Access at: `http://localhost:8888/`

Authentication is always on. Set a stable `access_token`, or leave it blank and
SentinelPi prints a generated one to the log on startup.

- **In a browser:** open `http://localhost:8888/` — you'll be redirected to a
  login page. Paste the token and sign in; a signed, HttpOnly, SameSite=Strict
  session cookie keeps you logged in (use *Log out* to clear it).
- **Programmatically** (curl, scripts): send the header
  `Authorization: Bearer yourtoken`.

The token is **never** accepted via the query string (`?token=...`) — that would
leak it into access logs, browser history, and `Referer` headers.

The dashboard uses server-sent events (`/api/events`) for live status, alert, and
response-action refreshes. Browsers authenticate the stream with the same signed
session cookie as the rest of the dashboard; if the stream is unavailable, the
page falls back to timed polling.

## Notifications

### Webhook (Slack, Discord, ntfy.sh, etc.)

```yaml
notifications:
  webhook_enabled: true
  webhook_url: "https://hooks.slack.com/services/T.../B.../xxx"
  webhook_min_severity: medium
  webhook_secret: "optional-shared-secret"
```

The webhook payload is a JSON POST:
```json
{
  "source": "SentinelPi",
  "hostname": "sentinelpi",
  "alert": {
    "severity": "high",
    "category": "port_scan",
    "title": "Port scan: 192.168.1.50 → 192.168.1.100",
    "description": "...",
    ...
  }
}
```

### ntfy (actionable push with Approve/Reject)

[ntfy](https://ntfy.sh) delivers push notifications to your phone. Beyond plain alerts, SentinelPi
attaches **Approve/Reject buttons** to notifications for responder actions awaiting approval, so you
can authorize a block or sinkhole from the lock screen without opening the dashboard.

```yaml
notifications:
  ntfy_enabled: true
  ntfy_server: "https://ntfy.sh"          # or your self-hosted server
  ntfy_topic: "sentinelpi-pick-something-unguessable"
  ntfy_token: ""                          # bearer auth to the ntfy server (optional)
  ntfy_min_severity: high
  # Where the Approve/Reject buttons call back to — the dashboard as reachable
  # from your phone — and its API token. Buttons appear ONLY when both are set.
  ntfy_dashboard_url: "https://pi.lan:8888"
  ntfy_dashboard_token: "<dashboard.access_token>"
```

Subscribe to the topic in the ntfy mobile app. When active response is **armed with approval
required** (`response.enabled: true`, `response.dry_run: false`, `response.require_approval: true`),
each pending action arrives as a notification whose Approve/Reject buttons POST to
`/api/responses/<id>/approve` and `/reject` with the dashboard bearer token. Because the buttons hit
the dashboard API, `ntfy_dashboard_url` must be reachable from the phone (e.g. over your LAN, VPN, or
Tailscale) and should be HTTPS so the token isn't sent in the clear.

### Email

```yaml
notifications:
  email_enabled: true
  email_smtp_host: "smtp.gmail.com"
  email_smtp_port: 465
  email_smtp_tls: true
  email_username: "you@gmail.com"
  email_password: "app-specific-password"
  email_from: "sentinelpi@gmail.com"
  email_to:
    - "you@example.com"
  email_min_severity: high
```

### Twilio SMS

SentinelPi can send high-signal alerts as SMS through Twilio Programmable Messaging. Keep
`sms_min_severity` at `critical` or `high` unless you intentionally want frequent texts; Twilio
charges per segment and long messages may be split by carriers.

```yaml
notifications:
  sms_enabled: true
  sms_account_sid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  sms_auth_token: ""                # optional when API key credentials are set
  sms_api_key_sid: "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  sms_api_key_secret: "<twilio-api-key-secret>"
  sms_from: "+15551234567"          # or set sms_messaging_service_sid instead
  sms_messaging_service_sid: ""
  sms_to:
    - "+15557654321"
  sms_min_severity: critical
```

Run `sentinelpi --check` after configuring SMS. The preflight sends a labelled test SMS so you can
verify credentials, sender registration, and delivery before trusting it for real alerts.

### SIEM export (syslog: ECS / CEF)

Stream alerts to a SIEM or log pipeline over syslog. Each alert is rendered in a SIEM-friendly
payload and wrapped in an RFC 5424 frame, so platforms like Splunk, Elastic, Graylog, QRadar, and
ArcSight can parse it directly.

- `siem_format`: `ecs` emits an [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
  JSON document (best for Elastic/Splunk); `cef` emits an ArcSight Common Event Format line (best for
  QRadar/ArcSight).
- `siem_transport`: `udp` sends one datagram per alert; `tcp` sends newline-delimited frames
  (RFC 6587 non-transparent framing) for reliable, ordered delivery.

```yaml
notifications:
  siem_enabled: true
  siem_format: ecs                  # ecs | cef
  siem_transport: udp               # udp | tcp
  siem_host: "10.0.0.5"             # collector / syslog receiver
  siem_port: 514
  siem_facility: local0             # user, daemon, or local0-local7
  siem_min_severity: low
```

Alert severity is mapped to the syslog severity (and to the 0-10 CEF scale / numeric ECS
`event.severity`), so collector-side severity routing works without extra parsing. Run
`sentinelpi --check` to send a labelled test event through the configured transport before relying
on it.

### OpenTelemetry export (OTLP/HTTP logs)

Export alerts as OpenTelemetry logs to any OTLP/HTTP logs endpoint — an
[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), Grafana Alloy/Loki, or a
vendor backend. Each alert is POSTed as an OTLP `LogsData` JSON document to the endpoint's `/v1/logs`
path. SentinelPi builds the JSON directly (no OpenTelemetry SDK dependency), so it stays light on a
Pi.

```yaml
notifications:
  otlp_enabled: true
  otlp_endpoint: "http://otel-collector:4318/v1/logs"
  otlp_headers:
    Authorization: "Bearer <token>"      # optional auth headers
  otlp_service_name: "sentinelpi"
  otlp_timeout_seconds: 10
  otlp_min_severity: low
```

Alert severity maps to the OTLP `SeverityNumber`/`SeverityText` (INFO/WARN/ERROR/FATAL bands); the
alert title becomes the log body, and host/category/confidence/etc. become log attributes
(`source.ip`, `event.category`, `sentinelpi.confidence`, …). Run `sentinelpi --check` to POST a
labelled test log to the collector before relying on it.

## Whole-Network Coverage (Phase 3)

By default SentinelPi sees its own host plus whatever the LAN segment lets it
sniff. To watch the *whole* network, use one or more of these.

### Span/mirror-port mode

Plug the capture interface into a switch **SPAN/mirror port** that receives a
copy of all subnet traffic, then enable mirror mode:

```yaml
network:
  interfaces: [eth0]      # the NIC cabled to the mirror port
  mirror_mode: true       # forces promiscuous capture of other hosts' unicast
```

Switch setup (varies by vendor):

- **Managed switch (generic):** configure a *port mirroring* / *SPAN* session
  with the uplink (or the ports you care about) as the **source** and the Pi's
  port as the **destination/monitor** port.
- **Cisco:** `monitor session 1 source interface Gi0/1` then
  `monitor session 1 destination interface Gi0/24`.
- **MikroTik/UniFi/etc.:** enable the "mirror"/"port isolation monitor" feature
  and point it at the Pi's port.

Mirror mode only makes capture promiscuous (required to see unicast between
*other* hosts). A dedicated capture NIC is recommended so the mirror flood
doesn't compete with the Pi's normal traffic.

### Flow ingestion (router/firewall)

See connections that never cross the Pi's segment by ingesting flow data from
the gateway. All sources are off by default and feed the same detectors as
packet capture.

```yaml
flow:
  # Linux conntrack (best when the Pi is the gateway/router)
  conntrack_enabled: false
  conntrack_interval_seconds: 10
  conntrack_command: conntrack          # falls back to /proc/net/nf_conntrack

  # NetFlow v5/v9/IPFIX — point your router/switch exporter at this host:port
  netflow_enabled: false
  netflow_bind_host: "0.0.0.0"
  netflow_port: 2055

  # pfSense/OPNsense filterlog — forward the firewall's syslog to the Pi and
  # write it to a file (rsyslog), then point filterlog_path at that file
  filterlog_enabled: false
  filterlog_path: /var/log/filter.log
  filterlog_interval_seconds: 5
```

## Whitelisting

Suppress alerts for known-good traffic:

```yaml
whitelist_ips:
  - "192.168.1.200"   # NAS that does lots of SMB

whitelist_domains:
  - "update.microsoft.com"
  - "ntp.ubuntu.com"

whitelist_ports:
  - 8080    # Internal web proxy
```

## Quiet Hours

Suppress non-critical alerts during sleeping hours:

```yaml
monitoring:
  quiet_hours_enabled: true
  quiet_hours_start: 23   # 11 PM
  quiet_hours_end: 7      # 7 AM
```

HIGH and CRITICAL alerts still fire during quiet hours.

## Storage & Retention

```yaml
storage:
  db_path: /var/lib/sentinelpi/sentinelpi.db
  retention_days: 30     # Auto-purge older records
  vacuum_interval_seconds: 86400
```

## Fine-Tuning Thresholds

Override individual thresholds independently of the sensitivity profile:

```yaml
thresholds:
  port_scan_ports_per_minute: 20
  connection_spike_factor: 4.0
  beacon_cv_threshold: 0.12
  beacon_min_intervals: 10
  ssh_failures_threshold: 15
  ssh_failures_window_seconds: 180
  arp_mac_change_window_seconds: 300
  traffic_spike_factor: 6.0
  dns_entropy_threshold: 4.0
  lateral_movement_dest_threshold: 5
```

## Validating Configuration

```bash
sentinelpi --check-config
# or
python -m sentinelpi.main --config /path/to/config.yaml --check-config
```

`--check-config` is a **static** check: it validates operator-facing values (CIDRs, ports, severity
names, responder backends, sensitivity profiles) and exits non-zero with actionable errors. It makes
no network calls, so it is safe to run anywhere, including CI.

### Active preflight: `--check`

```bash
sentinelpi --check
```

`--check` runs the same static validation and then **actively exercises your configured outputs**:

- **Notifiers** — connects to SMTP (authenticating, but sending no mail) and delivers a clearly
  labelled test notification through each enabled webhook / ntfy / SMS / SIEM / forward channel. This
  catches a wrong URL, bad token, unreachable collector, or failed auth before a real alert needs to
  go out.
- **Responders** — asks each enabled responder to *plan* a synthetic alert. Planning is
  side-effect-free, so **nothing is ever executed**; the output shows what each responder *would*
  do (e.g. `would: Block 203.0.113.10 (iptables)`).
- **Environment** — the optional files and binaries that *enabled* features depend on: GeoIP/ASN
  databases, the auth log, DHCP leases, file-integrity paths, packet-capture support (scapy), and
  responder backends (`iptables`/`nftables`, `arp`/`ip`, `pihole`/`unbound-control`, `/etc/hosts`).
  A missing dependency is reported as `WARN` — the feature will run degraded or disabled, but the
  daemon still starts, so it does **not** change the exit code.

Exit codes: `0` = all good, `2` = invalid config, `3` = a preflight probe failed. `WARN` rows
(degraded features) are informational and never cause a non-zero exit. Because `--check` delivers
real test notifications, run it interactively rather than in unattended CI.

## Backup & Restore

Every learned baseline — known destinations, hourly connection statistics, DNS domains, per-host
countries, active hours, and behavioural profiles — plus alerts and the device inventory live in the
single SQLite database at `storage.db_path`. Backing up that file therefore captures the sensor's
entire memory, so baselines (which can take days to learn) survive an SD-card failure or a Pi
re-image.

### Creating a backup

```bash
sentinelpi --config /etc/sentinelpi/sentinelpi.yaml --backup /mnt/usb/sentinelpi-$(date +%F).tar.gz
```

The snapshot is taken with SQLite's online backup API, so it is point-in-time consistent **even
while the daemon is running** — ideal for an unattended cron job to external storage. The archive is
a gzip-compressed tar containing the database plus a `manifest.json` (format tag, schema version,
SentinelPi version, creation time, and a SHA-256 checksum).

### Restoring a backup

Stop the service first so it is not writing to the database, then:

```bash
sentinelpi --config /etc/sentinelpi/sentinelpi.yaml --restore /mnt/usb/sentinelpi-2026-06-17.tar.gz
```

Restore verifies the checksum and runs a SQLite integrity check before installing the snapshot. Any
existing database is moved aside to `<db_path>.pre-restore-<timestamp>` rather than deleted, and
stale WAL/SHM sidecars are cleared. A snapshot from an **older** schema is accepted and upgraded by
the normal migration path on next startup; a snapshot from a **newer** schema is refused unless you
pass `--force`.

Exit codes: `0` = success, `4` = backup/restore failed (e.g. missing database, corrupt archive,
checksum mismatch, or newer schema without `--force`).
