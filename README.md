# Cyber Portfolio — Home Lab Projects

Hands-on home lab work built while transitioning from a NOC role into a SOC/cyber operations position. Focused on practical, self-directed learning across SIEM operations, detection engineering, offensive security fundamentals, and network/packet analysis — using real infrastructure rather than pre-built training environments, including the troubleshooting that comes with that.

## About Me

Currently working in a NOC with responsibility for enterprise patch management (SCCM, large network). CCNA-level networking background. Building this lab to develop hands-on SOC/cyber operations skills ahead of a role transition, with a particular focus on detection engineering, log/traffic analysis, and understanding attacks from both the offensive and defensive side.

## Lab Environment

- **Hypervisor:** Microsoft Hyper-V
- **Network:** Segmented Internal virtual switch with Internet Connection Sharing (ICS) for controlled internet egress
- **Hosts:**
  - Windows 11 (management workstation, VPN client, Wireshark analysis, domain workstation)
  - Ubuntu Server 24.04 — OpenVPN server
  - Ubuntu Server 24.04 — Wazuh SIEM (manager, indexer, dashboard)
  - Ubuntu Server 24.04 Minimal — Docker host (vulnerable application targets)
  - Windows Server 2019 Core — Active Directory Domain Controller (lab.local)
  - Kali Linux — Attack machine (Impacket, NetExec, John the Ripper)

## Repository Structure

Projects are grouped by category rather than listed as a flat sequence, so the organization reflects the type of work rather than the order it was built in:

```
01-Detection-Engineering/
├── C2-Detection/
├── DNS-Tunneling/
├── Docker-Sim/
├── Lateral-Movement/
└── Suricata/

02-Active-Directory/
├── Active-Directory-Attack/
├── BloodHound-Enumeration/
└── Golden-Ticket/

03-Security-Infrastructure/
└── Home-Lab-SIEM-Deployment/

04-Local-AI-SOC-Tooling/
└── Screenshots/
```

A planned IOC enrichment tool (IP/domain/hash → reputation/DNS/WHOIS → structured SOC output) will also live in this category once built.

## Projects

### Detection Engineering

Custom Wazuh detection rules, decoder authoring, and network IDS work — closing visibility gaps and correlating multi-stage attack behavior rather than relying on default signatures.

**[Detecting C2 Beaconing: Custom Wazuh Detection Engineering](./01-Detection-Engineering/C2-Detection/README.md)**
A self-contained beacon simulator (Docker) used to generate realistic C2 check-in traffic, confirmed manually in Wireshark (consistent ~13s intervals, fixed 26-byte request size), then detected automatically via a custom multi-stage Wazuh decoder and frequency/timeframe correlation rule — built entirely from scratch, since no default Wazuh rule covers this behavior.
**Key skills:** Custom decoder authoring (multi-stage, regex field extraction), Wazuh frequency/timeframe correlation logic, `wazuh-logtest` for isolated rule diagnosis, behavioral pattern detection vs. single-event detection.

**[Detecting DNS Tunneling: Decoder Engineering and Multi-Tier Alert Escalation](./01-Detection-Engineering/DNS-Tunneling/README.md)**
Simulation of DNS tunneling — encoding stolen credentials into base32-encoded DNS subdomain labels transmitted as genuine DNS wire-format packets — with a three-tier Wazuh detection rule chain (individual query catch → domain-specific detection → high-volume escalation) and a two-stage custom decoder to extract structured fields.
**Key skills:** DNS protocol and tunneling mechanics, two-stage decoder design, regex field extraction debugging, three-tier rule escalation, Wireshark analysis on Docker bridge networks.

**[Simulated Network & Application-Layer Attack Detection](./01-Detection-Engineering/Docker-Sim/README.md)**
Docker host running OWASP Juice Shop, used to identify and close a real visibility gap — host-based monitoring has no native insight into containerized application traffic. Covers reverse proxy log collection, a custom detection rule for web attack patterns, and investigation of a rootcheck false positive.
**Key skills:** Docker deployment, SIEM visibility gap analysis, nginx reverse proxy logging, alert verification methodology.

**[Attack Traffic Analysis: SQL Injection & File Upload RCE](./01-Detection-Engineering/Docker-Sim/dvwa-attack-traffic-analysis.md)**
Hands-on offensive testing against DVWA (SQL injection, file upload to remote code execution), with all traffic captured and analyzed in Wireshark. Includes a full root-cause investigation of a TCP anomaly (Duplicate ACKs) and honest documentation of a partial exploitation failure alongside the successful RCE chain.
**Key skills:** Manual web exploitation, packet analysis (Wireshark), SQL injection mechanics, detection-visibility awareness, root-cause investigation.

**[Lateral Movement Detection: Web Shell Execution to Persistence](./01-Detection-Engineering/Lateral-Movement/README.md)**
Full post-exploitation attack chain — initial access via web shell RCE, host/network enumeration, lateral pivot to a second container, and persistence file drop — across a multi-container Docker environment, with Wazuh detection covering each stage, including a frequency/timeframe correlation rule that escalates multiple web shell commands into a confirmed attack chain alert.
**Key skills:** Attack chain simulation and correlation, container log architecture, built-in rule discovery before custom authoring, FIM-based persistence detection, operating in a noisy multi-alert environment.

**[Suricata Network IDS: Closing the Network Visibility Gap](./01-Detection-Engineering/Suricata/README.md)**
Suricata deployed as a network-based IDS on the Docker host, monitoring all three Docker bridge interfaces simultaneously. The Emerging Threats Open ruleset (52,238 signatures) independently corroborated the C2 beacon activity already caught by Wazuh's log-correlation rules, and eve.json output was unified into the existing Wazuh dashboard.
**Key skills:** Network IDS deployment, multi-interface packet capture, Emerging Threats ruleset management, host-based vs. network-based detection paradigm comparison, cross-detection corroboration.

### Active Directory

A complete, purpose-built AD attack lab (Windows Server 2019 Core DC, Kali attack machine, domain-joined Windows 11 workstation) demonstrating total domain compromise from a single unprivileged account, detected and analyzed end-to-end.

**[Active Directory Attack Lab: Kerberoasting, Password Spraying, Credential Dumping, and Pass-the-Hash](./02-Active-Directory/Active-Directory-Attack/README.md)**
Full post-exploitation chain relevant to SANS SEC504: Kerberoasting → password spraying → DCSync credential dumping → Pass-the-Hash, monitored end-to-end by Wazuh with Windows audit logging. Total time from first attack to SYSTEM: ~10 minutes from one standard domain user account.
**Key skills:** Kerberoasting, offline hash cracking, lockout-safe password spraying, DCSync, Pass-the-Hash, Windows Security Event Log analysis (4624/4625/4769), MITRE ATT&CK mapping, PICERL framework application.

**[BloodHound AD Enumeration: Attack Path Analysis](./02-Active-Directory/BloodHound-Enumeration/README.md)**
BloodHound deployed against the lab's AD environment to map every domain relationship as a graph and surface attack paths automatically. SharpHound collected 97 objects in 26 seconds authenticated as an unprivileged standard user, independently corroborating the manual Kerberoasting result through graph analysis.
**Key skills:** BloodHound/SharpHound deployment, AD graph-based attack path analysis, Kerberoastable account identification, defensive use of attack tooling, SharpHound detection awareness.

**[Golden Ticket Attack: Forging Persistent Domain Admin Access](./02-Active-Directory/Golden-Ticket/README.md)**
Using the krbtgt hash captured during DCSync to forge a Kerberos Golden Ticket entirely offline, then authenticating with the forged ticket for a SYSTEM shell — with an honest documentation of the detection gap (Wazuh caught the service-installation consequence, not the ticket authentication itself).
**Key skills:** Golden Ticket forgery (Impacket ticketer), Kerberos ticket cache manipulation, offline credential exploitation, detection gap analysis.

### Security Infrastructure

The platform everything above runs on and reports into.

**[Home Lab SIEM Deployment](./03-Security-Infrastructure/Home-Lab-SIEM-Deployment/README.md)**
Deployment of a self-hosted OpenVPN server with ECDH-based encryption and split-tunnel configuration, monitored end-to-end by a Wazuh SIEM. Covers agent management, File Integrity Monitoring, custom detection rule authoring, and a real, unplanned infrastructure incident — a disk-full condition that cascaded into API failures and database corruption risk — diagnosed and resolved from first principles.
**Key skills:** SIEM deployment, custom detection rules, Linux troubleshooting, root cause analysis, incident response.

See also: [OpenVPN Server Configuration](./03-Security-Infrastructure/Home-Lab-SIEM-Deployment/OpenVPN-Server-Configuration.md) — verified ECDH curve (secp384r1), cipher suite, and split-tunnel design rationale.

### AI & Automation

Local, private-by-design AI tooling for SOC work — evaluated the same way the detection rules above are evaluated: systematically, with honest documentation of what didn't work.

**[Local AI SOC Analyst — Deploying, Evaluating and Fine-Tuning LLMs for Security Operations](./04-Local-AI-SOC-Tooling/README.md)**
Systematic evaluation of locally-hosted LLMs as SOC analyst assistants — alert triage, MITRE ATT&CK mapping, multi-alert chain analysis, detection rule generation, false positive analysis — entirely on local hardware, so no alert data ever leaves the security perimeter. Six model configurations tested in progression from a 3.4/10 general-purpose baseline to a 7.2/10 LoRA fine-tuned Foundation-Sec model. A second, hypothesis-driven fine-tuning iteration then targeted the three specific tests the first pass scored weakest on (hallucination resistance, decoder generation, false positive reasoning), raising the average to 8.6/10. Along the way, an apparent total model collapse (four of five tests scoring zero) turned out to be a genuine evaluation-harness bug rather than a model failure — Ollama was returning a fully correct answer in a reasoning field the harness never read — documented as a finding in its own right rather than quietly patched over.
**Key skills:** LLM deployment (Ollama, Open WebUI), prompt engineering, RAG implementation, LoRA fine-tuning (Unsloth), CUDA environment management, hypothesis-driven dataset iteration targeting specific failure modes, LLM serving pipeline debugging, AI evaluation methodology and variance awareness.

## Recurring Themes Across These Projects

- **Real incidents, not staged ones.** The infrastructure problems documented here happened during genuine testing, not as scripted exercises — and are documented with the same rigor as the intended lab work.
- **Honest limitations, not just wins.** Where something didn't fully work as expected (POST body logging gaps, file extension mitigations, false positives, incomplete cross-technique correlation), that's documented explicitly rather than omitted.
- **Detection and offense together.** Each offensive test is paired with an assessment of what a defender would (or wouldn't) see — tying attacker technique directly to detection engineering.
- **Visibility gaps as a recurring theme.** Container log visibility has come up in three separate projects and been resolved three different ways — a pattern that demonstrates genuine depth of understanding of a core SIEM architectural constraint rather than a single lucky fix.
- **Speed of compromise.** The AD attack chain demonstrates total domain compromise in under 10 minutes from a single unprivileged user account — and the Golden Ticket project extends this to show how persistence can survive most standard remediation attempts.

## Next Steps

**In progress — SOC Investigation series:** reframing the technical work above into full investigation write-ups (timeline, confirmed vs. suspected findings, containment reasoning) rather than standalone tool builds:
- Investigation #1 — Phishing: Office macro delivery → PowerShell → C2 → compromised account → lateral movement
- Investigation #2 — Windows Endpoint Compromise: Sysmon, process trees, persistence, IOC hunting, containment/recovery
- Investigation #3 — Threat Hunting: hypothesis-driven hunt pivoting across Wazuh/Sysmon/AD/DNS/Suricata
- SOC automation: a small IOC enrichment tool (IP/domain/hash → reputation/DNS/WHOIS → structured output) supporting the investigations above

**Backlog:**
- PICERL incident response documentation — formally applying the incident handling framework to the disk-full cascading failure from the SIEM deployment project
- ACL abuse misconfigurations — add GenericWrite/WriteDACL relationships to demonstrate multi-hop BloodHound attack paths
- AD Certificate Services (ADCS) attacks — ESC1/ESC8 certificate template abuse
- SOAR integration — automated response playbooks triggered by existing Wazuh rules (Shuffle or TheHive + Cortex)
- Memory forensics basics using Volatility against a memory dump from the DC
- Custom Suricata rule for container-to-container pivot detection
- SSH honeypot (Cowrie) to capture real attacker behavior and feed into Wazuh