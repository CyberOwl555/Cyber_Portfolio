# Home Lab SIEM Deployment: Wazuh Monitoring for a Segmented VPN Environment

## Overview

This project extends an existing self-hosted OpenVPN server (Ubuntu 24.04, ECDH key exchange, split-tunnel configuration) with a full Wazuh SIEM deployment for centralized log collection, file integrity monitoring, and custom detection engineering. The goal was to build hands-on experience with SIEM operations, incident troubleshooting, and detection rule authoring — skills directly relevant to a SOC/cyber operations role.

## Architecture

- **Hypervisor:** Microsoft Hyper-V
- **Network:** Segmented internal virtual switch, isolating lab traffic from the home network
- **VPN Server:** Ubuntu 24.04 Server, OpenVPN with ECDH-based encryption, split-tunnel routing
- **SIEM:** Wazuh 4.8.2 (manager, indexer, and dashboard on a single Ubuntu 24.04 Server VM)
- **Monitored endpoints (agents):**
  - VPN server (Ubuntu, Linux agent)
  - Windows 11 host (Windows agent)

```
┌─────────────────────┐        ┌──────────────────────┐
│   Windows 11 Host    │        │   VPN Server (Ubuntu)│
│   Wazuh Agent        │        │   OpenVPN + Wazuh     │
│                       │        │   Agent               │
└──────────┬───────────┘        └───────────┬──────────┘
           │                                 │
           │        Hyper-V Internal Switch  │
           └────────────────┬────────────────┘
                             │
                  ┌──────────▼───────────┐
                  │   Wazuh Server        │
                  │   Manager + Indexer   │
                  │   + Dashboard          │
                  └───────────────────────┘
```

## What Was Built

### 1. SIEM Deployment
- Installed Wazuh's all-in-one stack (manager, indexer, dashboard) on a dedicated Ubuntu Server VM, separate from monitored assets
- Deployed Wazuh agents to both the VPN server and Windows 11 host, verified active connectivity via the manager

### 2. Detection Validation (Out-of-the-Box Rules)
Verified default detection logic by generating real attack-adjacent traffic and confirming alerts fired correctly:

| Test | Rule ID | Level | Description |
|---|---|---|---|
| Single SSH auth failure | 5760 | 5 | Baseline "one login failed" detection |
| Repeated SSH auth failure (same session) | 2502 | 10 | PAM-level escalation for multiple password attempts |
| File added (FIM) | 554 | 5 | Detected new file in monitored directory |
| File deleted (FIM) | 553 | 7 | Detected file removal — weighted higher than creation |

This confirmed the difference between **atomic-level logging** (single event, low severity) and **pattern-based detection** (correlated events, higher severity) — a core SIEM concept.

### 3. Custom Detection Rule Authoring
Rather than relying solely on default rules, I wrote custom rules tailored to this specific environment — elevating severity for changes to OpenVPN's configuration directory specifically, rather than treating it the same as any other file in `/etc`:

```xml
<group name="local,syscheck,openvpn,">

  <rule id="100010" level="12">
    <if_sid>550</if_sid>
    <field name="file">/etc/openvpn</field>
    <description>OpenVPN configuration file was modified - possible tampering</description>
    <group>openvpn_config_change,</group>
  </rule>

  <rule id="100011" level="13">
    <if_sid>553</if_sid>
    <field name="file">/etc/openvpn</field>
    <description>OpenVPN configuration file was DELETED - critical VPN integrity event</description>
    <group>openvpn_config_change,</group>
  </rule>

</group>
```

**Design rationale:** These rules use Wazuh's `if_sid` inheritance model — chaining off the base FIM rules (550 = modified, 553 = deleted) rather than writing new decoder logic from scratch. This demonstrates understanding of Wazuh's rule correlation hierarchy and the principle of **risk-weighting detection based on asset criticality** — a VPN config change is a materially different risk than an arbitrary file change elsewhere on the system.

Both rules were tested and confirmed firing correctly, with Wazuh automatically mapping the events to relevant MITRE ATT&CK techniques (e.g., T1548.003 – Privilege Escalation/Defense Evasion, T1078 – Valid Accounts) alongside the custom alerts.

### 4. Incident Response: Self-Inflicted Outage and Recovery

Partway through testing, the Wazuh stack went down. Rather than being a scripted exercise, this was a real, unplanned failure that required live troubleshooting — arguably the most valuable part of the project from a skills-demonstration standpoint.

**Timeline of the incident:**

1. **Symptom:** Dashboard became unreachable; API returned `429` (rate limit) errors followed by malformed JSON responses.
2. **Root cause identified:** `df -h` revealed the root filesystem was at 100% capacity.
3. **Investigation:** Used `du -h --max-depth` recursively to isolate the source, tracing it to `/var/ossec/queue/vd` and `/var/ossec/queue/vd_updater` — Wazuh's vulnerability detector feed cache — which had grown to ~12GB, consuming nearly all available disk on the lab VM.
4. **Secondary issue discovered:** A leftover SQLite `-journal` file on an agent database indicated a write operation had been interrupted mid-transaction when the disk filled — a known risk for database corruption. Ran `PRAGMA integrity_check` against all agent databases to confirm integrity before restarting services.
5. **Compounding issue:** An overly broad `pkill -9 -f wazuh` used to clear stuck processes during cleanup also killed the dashboard service via `SIGKILL`, initially misread as a possible out-of-memory event. Confirmed via `dmesg` and `free -h` that memory was not the cause, and correctly attributed the kill signal to the cleanup command itself.
6. **Resolution:** Cleared the bloated feed cache, restarted services in correct dependency order (indexer → manager → dashboard), and verified database integrity before bringing the manager back online.
7. **Secondary flare-up:** After recovery, the dashboard's authentication service entered a rapid retry loop, re-triggering the same rate limit. Diagnosed via `api.log` request patterns (`wazuh-wui` making dozens of authentication calls per second) and resolved by restarting the dashboard service cleanly.

**Root cause summary:** Unbounded vulnerability-feed downloads on a disk-constrained lab VM caused a full-disk condition, which cascaded into API failures, a corrupted-journal risk on an agent database, and a self-inflicted service kill during recovery — three distinct but related failure modes traced back to a single root cause.

**Remediation and hardening applied:**
- Cleared and rebuilt the vulnerability detector cache
- Verified all agent databases passed integrity checks post-recovery
- Documented the correct service restart order for this stack (indexer → manager → dashboard) to avoid resource contention on future restarts

**Follow-up hardening identified (planned):**
- Restrict the vulnerability detector to only sync feeds relevant to the deployed OS (Ubuntu) rather than all supported distributions
- Expand the VM's disk allocation to provide operational headroom
- Configure log rotation / index lifecycle policies to prevent unbounded growth going forward

## Skills Demonstrated

- SIEM deployment and agent management (Wazuh)
- File Integrity Monitoring configuration (realtime syscheck)
- Custom detection rule authoring using Wazuh's rule inheritance model (`if_sid`)
- Linux system administration and troubleshooting (disk management, systemd, SQLite)
- Root cause analysis across a multi-stage cascading failure
- Understanding of severity/risk weighting in detection logic
- Familiarity with MITRE ATT&CK mapping in detection output
- Network segmentation using Hyper-V virtual switches

## Next Steps

- Custom rule for OpenVPN connection-level events (client auth failures, unusual connect/disconnect patterns) — service-level detection to complement the file-level detection built here
- Vulnerability detector feed tuning
- Expand FIM/log monitoring to include Windows-specific detections (e.g., PowerShell logging, Windows Defender events)
