# SentinelPi — Troubleshooting Guide

## Common Issues

### "No config file found; using built-in defaults"

SentinelPi can't find `sentinelpi.yaml`. Either:
- Set the `SENTINELPI_CONFIG` environment variable
- Pass `--config /path/to/sentinelpi.yaml`
- Place the file in one of the default search paths

### "scapy not available — packet-level capture disabled"

Scapy is not installed in the active Python environment. Fix:
```bash
source venv/bin/activate
pip install scapy
```

Without scapy, SentinelPi falls back to `/proc/net` polling, which works but provides less detail (no DNS packet monitoring, no real-time ARP event processing).

### "Packet capture requires root or CAP_NET_RAW"

Two solutions:
1. **Grant capability** (recommended):
   ```bash
   REAL_PYTHON=$(readlink -f venv/bin/python3)
   sudo setcap cap_net_raw+eip "$REAL_PYTHON"
   ```
2. **Run as root** (not recommended for production):
   ```bash
   sudo venv/bin/python -m sentinelpi.main
   ```

### Dashboard not accessible

- Default bind is `127.0.0.1:8888` — only accessible from the Pi itself
- To access from another machine, either:
  - SSH tunnel: `ssh -L 8888:localhost:8888 pi@sentinelpi.local`
  - Change config: `dashboard.host: "0.0.0.0"` (understand the security implications)
- Check if the port is in use: `ss -tlnp | grep 8888`

### Too many false positive alerts

1. **Add trusted devices** to `trusted_devices` in config
2. **Whitelist** known-good IPs, domains, and ports
3. **Switch to conservative** sensitivity profile
4. **Increase individual thresholds** in the `thresholds` section
5. **Enable quiet hours** if you get alerts from overnight automated tasks
6. **Mute specific alerts** via the dashboard "Mute" button

### Not enough alerts / missing detections

1. **Switch to aggressive** sensitivity profile
2. **Lower thresholds** (e.g., `port_scan_ports_per_minute: 5`)
3. **Enable packet capture** (`packet_capture_enabled: true`) for better coverage
4. **Check baseline learning** — detectors are less sensitive during the learning phase
5. **Verify the interface** — make sure the correct network interface is configured

### High CPU usage on Raspberry Pi

1. **Disable packet capture** (`packet_capture_enabled: false`) — the biggest CPU consumer
2. **Add BPF filter exclusions** if there's chatty traffic (e.g., multicast)
3. **Reduce log verbosity** (`logging.level: WARNING`)
4. **Check the event queue size** in logs — if consistently near capacity, events are being dropped

### Database growing too large

1. **Reduce retention**: `storage.retention_days: 7`
2. **Force cleanup**: Restart the service (purge runs on startup)
3. **Check DB size**: `ls -lh /var/lib/sentinelpi/sentinelpi.db`
4. **Manual vacuum**: `sqlite3 /var/lib/sentinelpi/sentinelpi.db "VACUUM;"`

### Auth log detector not working

1. **Check file exists**: `ls -la /var/log/auth.log`
2. **Check permissions**: The `sentinelpi` user needs read access. Add to `adm` group:
   ```bash
   sudo usermod -aG adm sentinelpi
   ```
3. **Check log format**: SentinelPi expects standard Debian/Ubuntu auth.log format
4. **If using journald only**: Auth log monitoring requires a file-based log

### GeoIP lookups not working

1. Download the GeoLite2-Country database from MaxMind (free registration required)
2. Place at the path specified in `monitoring.geo_db_path`
3. Set `monitoring.geo_enabled: true`
4. Install the library: `pip install maxminddb`

## Diagnostic Commands

```bash
# Check service status and recent logs
sudo systemctl status sentinelpi
sudo journalctl -u sentinelpi -n 50

# Validate configuration
/opt/sentinelpi/venv/bin/python -m sentinelpi.main --check-config

# Check database integrity
sqlite3 /var/lib/sentinelpi/sentinelpi.db "PRAGMA integrity_check;"

# View recent alerts from database
sqlite3 /var/lib/sentinelpi/sentinelpi.db \
  "SELECT datetime(timestamp), severity, title FROM alerts ORDER BY timestamp DESC LIMIT 20;"

# View known devices
sqlite3 /var/lib/sentinelpi/sentinelpi.db \
  "SELECT ip, mac, hostname, vendor, suspicion_score FROM devices ORDER BY suspicion_score DESC;"

# Check current ARP table
cat /proc/net/arp

# Check active TCP connections
ss -tnp

# Check listening ports
ss -tlnp

# View JSON alert log
tail -20 /var/log/sentinelpi/alerts.json | python3 -m json.tool
```

## Getting Help

If you encounter an issue not covered here:

1. Check the logs: `sudo journalctl -u sentinelpi --since "1 hour ago"`
2. Run with debug logging: Set `logging.level: DEBUG` in config
3. Run interactively: `sudo -u sentinelpi /opt/sentinelpi/venv/bin/python -m sentinelpi.main`
