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
