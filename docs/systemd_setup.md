# SentinelPi — systemd Setup Guide

## Automatic Installation

The install script handles everything:

```bash
sudo bash scripts/install.sh
```

This creates the service at `/etc/systemd/system/sentinelpi.service`.

## Manual Installation

If you prefer to set things up manually:

### 1. Create the system user

```bash
sudo useradd --system --shell /usr/sbin/nologin --home-dir /opt/sentinelpi sentinelpi
sudo usermod -aG adm sentinelpi   # For auth log access
```

### 2. Create directories

```bash
sudo mkdir -p /opt/sentinelpi /etc/sentinelpi /var/lib/sentinelpi /var/log/sentinelpi
sudo chown sentinelpi:sentinelpi /opt/sentinelpi /var/lib/sentinelpi /var/log/sentinelpi
```

### 3. Set up the virtual environment

```bash
sudo -u sentinelpi python3.11 -m venv /opt/sentinelpi/venv
sudo cp -r src/sentinelpi /opt/sentinelpi/
sudo cp requirements.txt /opt/sentinelpi/
sudo -u sentinelpi /opt/sentinelpi/venv/bin/pip install -r /opt/sentinelpi/requirements.txt
```

### 4. Grant packet capture capability

```bash
REAL_PYTHON=$(readlink -f /opt/sentinelpi/venv/bin/python3)
sudo setcap cap_net_raw+eip "$REAL_PYTHON"
```

### 5. Install the config

```bash
sudo cp config/sentinelpi.yaml /etc/sentinelpi/sentinelpi.yaml
sudo chown root:sentinelpi /etc/sentinelpi/sentinelpi.yaml
sudo chmod 640 /etc/sentinelpi/sentinelpi.yaml
```

### 6. Install and enable the service

```bash
sudo cp systemd/sentinelpi.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinelpi
sudo systemctl start sentinelpi
```

## Service Management

```bash
# Start/stop/restart
sudo systemctl start sentinelpi
sudo systemctl stop sentinelpi
sudo systemctl restart sentinelpi

# Check status
sudo systemctl status sentinelpi

# Follow logs in real-time
sudo journalctl -u sentinelpi -f

# View last 100 lines
sudo journalctl -u sentinelpi -n 100

# View logs since last boot
sudo journalctl -u sentinelpi -b
```

## Resource Limits

The service file includes resource constraints suitable for Raspberry Pi:

```ini
MemoryMax=256M     # Hard memory limit
CPUQuota=80%       # Leave 20% for other processes
LimitNOFILE=65536  # File descriptor limit
```

Adjust in `/etc/systemd/system/sentinelpi.service` if needed, then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sentinelpi
```

## Security Hardening

The service file includes systemd security features:

- `NoNewPrivileges=yes` — Cannot gain new privileges after startup
- `ProtectSystem=strict` — Filesystem is read-only except allowed paths
- `ProtectHome=read-only` — Home directories are read-only
- `PrivateTmp=yes` — Private /tmp
- `SystemCallFilter=@system-service` — Restricted system calls
- `ReadWritePaths=` — Only `/var/lib/sentinelpi` and `/var/log/sentinelpi` are writable

## mTLS for the sensor → collector link (Phase 3)

In a multi-host deployment, sensors forward alerts to a collector's
`/api/ingest`, authenticated with the shared `cluster.collector_key`. For
mutual TLS, terminate client-cert verification at a reverse proxy in front of
the collector (the bundled waitress server does not do client-cert auth itself).

**Sensor side** — present a client cert and verify the collector:

```yaml
cluster:
  role: sensor
  collector_url: "https://collector.lan/api/ingest"
  collector_key: "<shared-secret>"
  tls_client_cert: /etc/sentinelpi/sensor.crt
  tls_client_key:  /etc/sentinelpi/sensor.key
  tls_ca_cert:     /etc/sentinelpi/ca.crt   # verifies the collector's cert
```

**Collector side** — require the proxy to have verified the client cert:

```yaml
cluster:
  collector_key: "<shared-secret>"
  ingest_require_verified_header: true   # demands X-SentinelPi-Client-Verified: SUCCESS
```

**nginx** terminating mTLS and forwarding to the local collector (waitress on
`127.0.0.1:8888`):

```nginx
server {
    listen 443 ssl;
    server_name collector.lan;

    ssl_certificate     /etc/sentinelpi/collector.crt;
    ssl_certificate_key /etc/sentinelpi/collector.key;
    ssl_client_certificate /etc/sentinelpi/ca.crt;
    ssl_verify_client on;                 # reject clients without a valid cert

    location /api/ingest {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header X-SentinelPi-Client-Verified $ssl_client_verify;
    }
}
```

With `ingest_require_verified_header: true`, the collector rejects (403) any
request the proxy didn't mark `SUCCESS`, so the shared key alone can't be
replayed without a valid client certificate.

## Troubleshooting

### Service won't start

```bash
# Check for errors
sudo systemctl status sentinelpi
sudo journalctl -u sentinelpi --no-pager -l

# Validate config
sudo -u sentinelpi /opt/sentinelpi/venv/bin/python -m sentinelpi.main --check-config

# Test manually
sudo -u sentinelpi /opt/sentinelpi/venv/bin/python -m sentinelpi.main
```

### Packet capture not working

```bash
# Verify capability is set
getcap /opt/sentinelpi/venv/bin/python3*

# Should show:
# /opt/sentinelpi/venv/bin/python3.11 cap_net_raw=eip

# If missing, re-apply:
REAL_PYTHON=$(readlink -f /opt/sentinelpi/venv/bin/python3)
sudo setcap cap_net_raw+eip "$REAL_PYTHON"
```

### Too many restarts

Check `StartLimitIntervalSec` and `StartLimitBurst` in the service file. Default allows 5 restarts in 5 minutes before giving up.

```bash
# Reset the failure counter
sudo systemctl reset-failed sentinelpi
sudo systemctl start sentinelpi
```
