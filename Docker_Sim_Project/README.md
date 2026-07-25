# Simulated Network & Application-Layer Attack Detection with Wazuh

## Overview

This project extends the existing Wazuh SIEM lab (see companion write-up: *Home Lab SIEM Deployment*) by adding a third monitored host — a Docker container platform running a deliberately vulnerable web application — to simulate application-layer attacks and build detection coverage beyond host-level monitoring (FIM, authentication, rootcheck).

The goal was to move from "monitoring individual machines" to "monitoring a small simulated network," and to specifically address a real visibility gap: **Wazuh's default configuration has no insight into what happens inside a web application**, only what happens on the host underneath it.

## Architecture

- **Hypervisor:** Microsoft Hyper-V
- **Network:** Internal virtual switch (`Operator-Core-Switch`) with Internet Connection Sharing (ICS) enabled on the Windows host, providing controlled internet egress to an otherwise isolated lab subnet (`192.168.137.0/24`)
- **New host:** Ubuntu Server 24.04 Minimal running Docker Engine
- **Target application:** OWASP Juice Shop (intentionally vulnerable web app), reverse-proxied through nginx
- **Monitoring:** Wazuh agent on the Docker host, log collection pointed at nginx's access/error logs

```
┌──────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
│  Windows 11 Host      │      │  VPN Server (Ubuntu)   │      │  Docker Host (Ubuntu)  │
│  Wazuh Agent           │      │  OpenVPN + Wazuh Agent │      │  nginx reverse proxy    │
│                        │      │                        │      │  → Juice Shop (Docker)  │
│                        │      │                        │      │  + Wazuh Agent          │
└──────────┬─────────────┘      └───────────┬────────────┘      └───────────┬────────────┘
           │                                 │                              │
           │        Internal Switch (192.168.137.0/24, via ICS)             │
           └─────────────────────────────────┴──────────────────────────────┘
                                              │
                                   ┌──────────▼───────────┐
                                   │   Wazuh Server        │
                                   │   Manager + Indexer   │
                                   │   + Dashboard          │
                                   └───────────────────────┘
```

## What Was Built

### 1. Network Segmentation and Reconfiguration

The lab network was migrated from Hyper-V's Default Switch to a dedicated **Internal switch**, isolating all lab traffic from the home network while retaining host-to-VM connectivity. Internet access for the isolated subnet was provided via **Internet Connection Sharing (ICS)** on the Windows host, which required re-addressing the entire lab (`10.10.10.x` → `192.168.137.x` to match ICS's default range) and updating every Wazuh agent, the OpenVPN configuration, and static IP assignments across all VMs.

This reinforced a practical lesson: network re-architecture has a cost across every dependent system (agent registration, service configs, firewall assumptions), and changes need to be rolled out and verified systematically rather than all at once.

### 2. Docker Host Deployment

- Ubuntu Server 24.04 Minimal installed as a dedicated container host, kept separate from the VPN and SIEM infrastructure
- Docker Engine installed via the official repository (not the snap package)
- OWASP Juice Shop deployed as a containerized target application

### 3. Identifying and Closing a Visibility Gap

Initial manual attacks against Juice Shop (SQL injection login bypass, reflected XSS) produced **no corresponding alerts** in Wazuh, despite the Wazuh agent being active and healthy on the Docker host. Investigation confirmed this was expected behavior, not a fault: the host-level agent monitors the operating system (file integrity, authentication, process anomalies) but has no native visibility into HTTP traffic terminating inside a container.

**Remediation:** Deployed nginx as a reverse proxy in front of Juice Shop, running directly on the Docker host (not containerized) so its logs are trivially accessible to the host-based Wazuh agent. Configured Wazuh's log collector to ingest nginx's access and error logs.

This closed the gap — subsequent attack attempts against the login endpoint produced real, parsed alerts (Wazuh's built-in web log decoder correctly identified HTTP 500 responses via rule 31122), confirming the full pipeline: attack → nginx log → Wazuh log collector → decoder → rule match → dashboard alert.

**Known limitation identified (and documented rather than silently ignored):** Standard nginx access logs only capture the request URL, not the POST body. This means SQL injection payloads submitted via login forms (e.g., `' OR 1=1--`) are not visible in the raw log — only the resulting HTTP status code is. A production deployment would need either extended logging (capturing request bodies, at a performance/storage cost) or a dedicated WAF to gain payload-level visibility. This trade-off was documented as identified follow-up work rather than solved in this phase.

### 4. Custom Detection Rule: Application-Layer Attack Pattern

Rather than relying on the generic "web server 500 error" rule, a custom rule was authored to specifically flag repeated failures against the authentication endpoint — a stronger indicator of malicious probing than an isolated error:

```xml
<group name="local,web,attack,">

  <rule id="100020" level="10">
    <if_matched_sid>31122</if_matched_sid>
    <url>/rest/user/login</url>
    <description>Repeated 500 errors on login endpoint - possible injection attempt</description>
    <group>web_attack,authentication_attack,</group>
  </rule>

</group>
```

This rule uses `if_matched_sid` to build on Wazuh's existing web-log decoder rather than duplicating decoder logic, and narrows scope specifically to the authentication endpoint — demonstrating targeted, asset-aware detection rather than a blanket rule.

### 5. Investigating a Rootcheck False Positive

During testing, Wazuh's rootcheck module flagged `/usr/bin/diff` as a "Trojaned version" using a legacy generic signature (matching strings like `bash`, `/bin/sh`, `/dev/` inside the binary). Rather than accepting or dismissing the alert outright, this was investigated:

- `file /usr/bin/diff` confirmed the file was a genuine compiled ELF binary, not a shell-script wrapper (the actual threat this signature was designed to catch)
- `dpkg -V diffutils` confirmed the installed binary matched Ubuntu's official package checksums exactly, with no modification

**Conclusion:** Confirmed false positive, attributable to Wazuh's legacy signature-based rootcheck detection method predating modern binary packaging conventions. Documented as an accepted, verified false positive rather than a suppressed alert — the distinction being that verification occurred before any decision to ignore it.

## Skills Demonstrated

- Docker deployment and container-based lab design
- Identifying and closing SIEM visibility gaps (host-level vs. application-level monitoring)
- Reverse proxy configuration (nginx) for logging and monitoring purposes
- Custom detection rule authoring using Wazuh's rule-chaining model (`if_matched_sid`)
- Network segmentation and internet egress design (Internal switch + ICS)
- Large-scale reconfiguration management across multiple dependent systems following a network change
- Alert triage and false-positive verification methodology (not just detection, but validation)
- Documenting known limitations and follow-up work honestly, rather than overstating completeness

## Next Steps / Identified Follow-Up Work

- Extend nginx logging to capture POST request bodies for full payload-level SQLi/XSS visibility (with documented performance trade-offs)
- Author additional custom rules for reflected XSS patterns and other OWASP Top 10 categories
- Introduce a second "workstation" container and simulate lateral movement between containers, to build cross-host correlation rules
- Tune or disable the legacy rootcheck trojan-binary signature to reduce noise, once its false-positive behavior on this OS baseline is fully characterized
