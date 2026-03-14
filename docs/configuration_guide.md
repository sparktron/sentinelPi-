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
  access_token: ""      # Set a token to require authentication
```

Access at: `http://localhost:8888/`

If you set an `access_token`, provide it via:
- Query parameter: `http://localhost:8888/?token=yourtoken`
- Header: `Authorization: Bearer yourtoken`

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
