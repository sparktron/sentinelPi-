# SentinelPi

Lightweight defensive network anomaly monitor designed for continuous operation on Raspberry Pi.

SentinelPi passively monitors your home lab or small office network, builds a behavioral baseline over time, and flags suspicious activity with clear, human-readable explanations. It detects unauthorized devices, ARP spoofing, port scanning, beaconing malware, DNS abuse, lateral movement, SSH brute force, and other anomalies.

**This is a monitoring and detection tool only.** It contains no offensive capabilities, exploit code, traffic injection, or active retaliation features.

## Features

- **Device Inventory** — Tracks all LAN devices by MAC/IP, detects new and rogue devices
- **ARP Spoofing Detection** — Monitors for gateway MAC changes and conflicting ARP replies
- **Port Scan Detection** — Identifies hosts probing many ports or sweeping the subnet
- **Beacon Detection** — Finds regular outbound connection intervals (C2 check-in patterns)
- **Connection Monitoring** — Detects spikes, new external destinations, suspicious ports
- **DNS Anomaly Detection** — Flags DGA domains, DNS tunneling, NXDOMAIN floods
- **Lateral Movement Detection** — Identifies admin protocol fan-out between internal hosts
- **Auth Log Monitoring** — SSH brute force, new logins, sudo abuse
- **Behavioral Baseline** — Learns normal traffic patterns; flags deviations with z-score analysis
- **Web Dashboard** — Local Flask-based UI with real-time alerts, device inventory, and controls
- **Alert Management** — Deduplication, cooldowns, severity levels, acknowledgment, muting
- **Structured Alerting** — Console output, rotating JSON log, optional email/webhook notifications

## Requirements

- Raspberry Pi 4 or newer (or any Debian-based Linux)
- Python 3.11+
- Network interface in the monitored subnet
- Root or `CAP_NET_RAW` for packet capture (optional; proc polling works without root)

## Quick Start

### Development / Testing

```bash
# Clone and enter the project
cd sentinelPi-

# Set up the virtual environment
bash scripts/setup_venv.sh
source venv/bin/activate

# Run tests
python -m pytest tests/ -v

# Check config
SENTINELPI_CONFIG=config/sentinelpi.yaml python -m sentinelpi.main --check-config

# Start monitoring (may need sudo for packet capture)
SENTINELPI_CONFIG=config/sentinelpi.yaml python -m sentinelpi.main
```

### Production Install (Raspberry Pi)

```bash
# Install as a systemd service
sudo bash scripts/install.sh

# Edit configuration
sudo nano /etc/sentinelpi/sentinelpi.yaml

# Start the service
sudo systemctl start sentinelpi
sudo systemctl status sentinelpi

# View logs
sudo journalctl -u sentinelpi -f

# Open dashboard
# http://localhost:8888/
```

## Configuration

The configuration file (`config/sentinelpi.yaml`) controls all behavior. Key settings:

| Section | What to configure |
|---------|-------------------|
| `network` | Interface, subnet, gateway IP/MAC |
| `trusted_devices` | Your known devices (suppresses new-device alerts) |
| `monitoring.sensitivity_profile` | `conservative`, `balanced`, or `aggressive` |
| `monitoring.packet_capture_enabled` | `true` for full capture, `false` for proc-only (no root) |
| `dashboard` | Host/port, access token |
| `notifications` | Email and webhook settings |
| `thresholds` | Fine-tune individual detector thresholds |
| `whitelist_*` | IPs, domains, ports to never alert on |

See [docs/configuration_guide.md](docs/configuration_guide.md) for full details.

## Architecture

```
                    ┌─────────────────────┐
                    │   Packet Capture    │ (scapy, optional)
                    │   /proc Readers     │ (no root needed)
                    │   Auth Log Tailer   │
                    └─────────┬───────────┘
                              │ events
                    ┌─────────▼───────────┐
                    │     Detectors       │
                    │  ARP │ Port Scan    │
                    │  Beacon │ DNS       │
                    │  Connection │ Auth  │
                    │  Lateral Movement   │
                    └─────────┬───────────┘
                              │ alerts
              ┌───────────────▼────────────────┐
              │         Alert Manager          │
              │  dedup │ cooldown │ routing    │
              └──┬──────────┬──────────┬───────┘
                 │          │          │
          ┌──────▼──┐  ┌────▼───┐  ┌───▼────┐
          │ Console │  │ SQLite │  │ Email  │
          │  JSON   │  │   DB   │  │Webhook │
          └─────────┘  └────────┘  └────────┘
                          │
                    ┌─────▼──────┐
                    │  Flask UI  │
                    │ Dashboard  │
                    └────────────┘
```

### Modules

| Module | Purpose |
|--------|---------|
| `capture/` | Packet sniffing (scapy) and `/proc/net` polling |
| `detectors/` | Rule-based and baseline-deviation anomaly detectors |
| `inventory/` | Device tracking, MAC/IP correlation |
| `baseline/` | Welford online statistics, behavioral baseline |
| `alerts/` | Deduplication, cooldown, notification routing |
| `storage/` | SQLite persistence (WAL mode, thread-safe) |
| `ui/` | Flask web dashboard |
| `config/` | YAML configuration loading and validation |
| `utils/` | Network helpers, GeoIP lookup |

## Detection Capabilities

| Detector | What It Finds | Method |
|----------|---------------|--------|
| ARP | Gateway MAC changes, ARP conflicts, reply floods | Rule-based |
| Port Scan | Vertical scans, host sweeps | Sliding window counters |
| Beacon | Regular outbound intervals (malware C2) | Coefficient of variation |
| Connection | Count spikes, new destinations, new listening ports | Baseline z-score |
| DNS | DGA domains, tunneling, NXDOMAIN floods | Entropy + rate analysis |
| Lateral Movement | Admin protocol fan-out, new internal connections | Rule + baseline |
| Auth Log | SSH brute force, new logins, sudo abuse | Pattern matching |

## Alert Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| `info` | Informational, no action needed | New known domain queried |
| `low` | Minor anomaly, worth noting | New device from known vendor |
| `medium` | Suspicious, investigate when convenient | New SSH login from unseen IP |
| `high` | Likely malicious, investigate promptly | Port scan detected, ARP conflict |
| `critical` | Active threat indicator, act now | Gateway MAC changed (ARP poisoning) |

## Testing

```bash
source venv/bin/activate
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=sentinelpi --cov-report=term-missing
```

Test fixtures simulate:
- Normal home network traffic
- Port scan (100+ ports in 30 seconds)
- Beaconing malware (regular 60s intervals)
- ARP spoofing (gateway MAC change)
- SSH brute force (50 failures in 100 seconds)
- DNS tunneling (long encoded subdomains)
- DGA domain generation (high-entropy NXDOMAIN)

## Documentation

- [Threat Model & Scope](docs/threat_model.md)
- [Configuration Guide](docs/configuration_guide.md)
- [systemd Setup Guide](docs/systemd_setup.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security Considerations](docs/security_considerations.md)

## Safety Boundaries

SentinelPi is a **defensive monitoring tool**. It does NOT:

- Inject, modify, or forge network traffic
- Perform active exploitation or vulnerability scanning
- Harvest credentials or intercept encrypted traffic
- Execute man-in-the-middle attacks
- Auto-block hosts or modify firewall rules
- Provide remote shell access or persistence mechanisms
- Include any offensive security capabilities

## License

MIT License. See [LICENSE](LICENSE) for details.
