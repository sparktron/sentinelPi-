# SentinelPi — Security Considerations & Limitations

## What SentinelPi Is

SentinelPi is a **passive, defensive monitoring tool** for small networks. It observes traffic metadata and system logs to detect anomalies. It is not an intrusion prevention system (IPS), firewall, or antivirus.

## What SentinelPi Is NOT

- **Not an IPS** — It does not block, drop, or modify traffic
- **Not a firewall** — It does not control access
- **Not an antivirus** — It does not scan files for malware signatures
- **Not a SIEM** — It is a lightweight local tool, not an enterprise log aggregator
- **Not offensive tooling** — It contains no exploitation, injection, or attack capabilities

## Security of the Tool Itself

### Attack Surface

SentinelPi introduces the following attack surface:

| Component | Risk | Mitigation |
|-----------|------|------------|
| Flask dashboard | HTTP service on localhost | Binds to 127.0.0.1 by default; optional token auth |
| SQLite database | Contains network metadata | File permissions 640, owned by sentinelpi user |
| Packet capture | Requires CAP_NET_RAW | Granted via setcap, not by running as root |
| Config file | May contain webhook secrets | File permissions 640, owned by root:sentinelpi |
| Auth log access | Reads sensitive system logs | sentinelpi user added to adm group (read-only) |

### Hardening Recommendations

1. **Keep the dashboard on localhost.** Do not expose it to the network unless absolutely necessary. Use SSH tunnels for remote access.

2. **Set a dashboard access token** if exposing the dashboard beyond localhost.

3. **Do not run as root.** The install script creates a dedicated system user with minimal privileges. Only CAP_NET_RAW is granted.

4. **Protect the config file.** It may contain email passwords or webhook secrets. Default permissions are 640 (owner: root, group: sentinelpi).

5. **Keep the Pi updated.** `sudo apt update && sudo apt upgrade` regularly.

6. **Harden SSH on the Pi:**
   - Disable password authentication (use keys only)
   - Change the default port
   - Install fail2ban
   - SentinelPi will detect SSH brute force, but prevention is better than detection

7. **Secure the SQLite database.** It contains metadata about your network devices, traffic patterns, and DNS queries. Treat it as sensitive.

## Limitations

### Encrypted Traffic

SentinelPi cannot inspect encrypted payloads. It sees:
- Connection metadata (source/destination IP, port, timing, volume)
- DNS queries (if plaintext on port 53)

It does NOT see:
- HTTPS content
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) queries
- VPN tunnel contents
- SSH session contents

### Network Visibility

SentinelPi can only monitor traffic visible to the Pi's network interface:
- On a switched network: only traffic to/from the Pi, plus broadcast/multicast
- ARP traffic is broadcast — always visible
- Traffic between two other hosts may not be visible unless the Pi is on a mirror/span port

For better visibility, configure a **mirror port** on your switch if supported.

### Evasion

A sophisticated attacker aware of SentinelPi could evade detection by:
- Using encrypted channels (VPN, SSH tunnels)
- Randomizing beacon intervals significantly
- Spoofing MAC addresses to match trusted devices
- Using DNS-over-HTTPS instead of plaintext DNS
- Staying below alert thresholds
- Operating during quiet hours (only non-critical alerts are suppressed)

### False Positives

Common sources of false positives:
- **IoT devices** with unusual traffic patterns (smart home devices, cameras)
- **Software updates** causing temporary connection spikes
- **Cloud services** with many CDN endpoints (appearing as "new destinations")
- **DHCP lease renewals** causing apparent IP changes
- **Network printers** and **NAS devices** with regular polling patterns (may resemble beaconing)

Mitigate by adding trusted devices and adjusting sensitivity.

### False Negatives

SentinelPi may miss:
- **Slow, low-volume attacks** that stay below thresholds
- **Attacks during learning phase** (first 24 hours by default)
- **Attacks that mimic normal traffic patterns** after observing the baseline
- **Exploits that don't generate network anomalies** (local privilege escalation, fileless malware)

## Data Privacy

SentinelPi collects and stores:
- IP and MAC addresses of all devices on your LAN
- DNS query names (which domains devices are looking up)
- Connection metadata (source, destination, ports, timestamps)
- Auth log entries (usernames, source IPs of SSH attempts)
- Network traffic volume statistics

This data is stored locally in SQLite and log files. It is never transmitted externally unless you configure webhook or email notifications.

**Retention:** Configurable (default 30 days). Older records are automatically purged.

**If deploying on a shared network:** Ensure you have authorization to monitor the network. In many jurisdictions, monitoring a network you do not own or administer may have legal implications.

## Defense in Depth

SentinelPi is one layer. A robust security posture also includes:

1. **Network segmentation** — Separate IoT, guest, and trusted devices
2. **Firewall rules** — Block unnecessary inbound/outbound traffic
3. **Up-to-date software** — Patch all devices regularly
4. **Strong authentication** — SSH keys, unique passwords, MFA where possible
5. **Encrypted communications** — HTTPS, SSH, VPN for remote access
6. **Backups** — Regular, tested backups of critical data
7. **Monitoring at multiple levels** — Network (SentinelPi) + endpoint + cloud
