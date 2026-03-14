# SentinelPi — Threat Model & Scope

## Overview

SentinelPi is designed to detect threats on small home lab or small office networks (1–50 devices) where the Pi has visibility into LAN traffic via its network interface.

## In-Scope Threats

### Network Layer
| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| **ARP spoofing / MITM** | Gateway MAC changes, conflicting ARP replies, ARP floods | High |
| **Rogue devices** | New MAC/IP combinations not in trusted list | High |
| **Port scanning** | Many unique dst ports from single source in short window | High |
| **Host sweeps** | Many unique internal dst IPs from single source | High |
| **Network reconnaissance** | Combination of scans, sweeps, and admin protocol probing | Medium |

### Application Layer
| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| **Malware beaconing** | Regular outbound connection intervals (low coefficient of variation) | Medium |
| **DNS tunneling** | Long subdomain labels, TXT queries with encoded data | Medium–High |
| **DGA domains** | High Shannon entropy in DNS queries, NXDOMAIN floods | Medium |
| **Data exfiltration** | Connection count spikes, unusual outbound destinations | Low–Medium |
| **C2 communication** | New external destinations + beacon patterns | Medium |

### Host Layer (Pi only)
| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| **SSH brute force** | Failure count/rate from auth log | High |
| **Unauthorized SSH access** | New source IP for successful login | Medium |
| **Privilege escalation** | Sensitive sudo commands in auth log | Low–Medium |
| **Backdoor services** | New listening ports not in baseline | Medium |
| **Config tampering** | File integrity hash changes (optional) | High |

### Lateral Movement
| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| **Admin protocol fan-out** | One host → many hosts via SSH/RDP/SMB | High |
| **Unexpected internal connections** | New (src→dst:admin_port) pairs after baseline | Medium |

## Out-of-Scope Threats

SentinelPi **cannot** detect:

- **Encrypted traffic content** — It sees connection metadata (IP, port, timing, volume) but cannot inspect encrypted payloads. HTTPS, SSH tunnel contents, and VPN traffic are opaque.
- **Attacks on other network segments** — Only monitors traffic visible on the Pi's interface. Traffic between two wireless clients on the same AP may not be visible.
- **Supply chain attacks** — Cannot verify software integrity on other devices.
- **Physical access attacks** — No physical security monitoring.
- **Advanced persistent threats** — Sophisticated APTs that carefully mimic normal traffic patterns may evade behavioral detection.
- **Zero-day exploits** — No signature database for vulnerability exploitation.
- **Encrypted DNS (DoH/DoT)** — DNS monitoring only works for plaintext DNS (port 53).

## Assumptions

1. **The Pi is not compromised.** If the monitoring host is compromised, all detection is unreliable.
2. **The Pi can see ARP traffic.** It must be on the same Layer 2 broadcast domain as monitored devices.
3. **The user controls the network.** This tool is for authorized monitoring of your own network.
4. **The baseline represents normal.** Initial learning phase should occur during typical usage.

## Trust Boundaries

```
┌─────────────────────────────────────────────┐
│              Your LAN (trusted zone)        │
│                                             │
│  [Pi/SentinelPi] ←→ [Router] ←→ [Devices]  │
│                                             │
└──────────────────┬──────────────────────────┘
                   │ gateway
                   ▼
           ┌───────────────┐
           │   Internet    │  (untrusted zone)
           └───────────────┘
```

- **SentinelPi trusts:** Its own config, the baseline it built, user-approved trusted devices.
- **SentinelPi does not trust:** Any network traffic, any device MAC/IP claim, any external IP.

## Risk Rating

| Risk | Impact | Likelihood | Notes |
|------|--------|------------|-------|
| False positive | Low | Medium | Mitigated by baseline + dedup + sensitivity tuning |
| False negative | Medium | Medium | Advanced threats may evade; defense in depth required |
| Resource exhaustion on Pi | Low | Low | Bounded queues, memory limits, retention policies |
| Attacker evading detection | Medium | Low | Randomized timing, encrypted tunnels can bypass |
| Compromised Pi | Critical | Low | Pi hardening is a prerequisite |
