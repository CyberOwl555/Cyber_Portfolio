# Cyber Portfolio — Home Lab Projects

Hands-on home lab work built while transitioning from a NOC role into a SOC/cyber operations position. Focused on practical, self-directed learning across SIEM operations, detection engineering, offensive security fundamentals, and network/packet analysis — using real infrastructure rather than pre-built training environments, including the troubleshooting that comes with that.

## About Me

Currently working in a NOC with responsibility for enterprise patch management (SCCM, large network). CCNA-level networking background. Building this lab to develop hands-on SOC/cyber operations skills ahead of a role transition, with a particular focus on detection engineering, log/traffic analysis, and understanding attacks from both the offensive and defensive side.

## Lab Environment

- **Hypervisor:** Microsoft Hyper-V
- **Network:** Segmented Internal virtual switch with Internet Connection Sharing (ICS) for controlled internet egress
- **Hosts:**
  - Windows 11 (management workstation, VPN client, Wireshark analysis)
  - Ubuntu Server 24.04 — OpenVPN server
  - Ubuntu Server 24.04 — Wazuh SIEM (manager, indexer, dashboard)
  - Ubuntu Server 24.04 Minimal — Docker host (vulnerable application targets)

## Projects

### 1. [Home Lab SIEM Deployment](./OpenVPN_Wazuh_Project/README.md)
Deployment of a self-hosted OpenVPN server with ECDH-based encryption and split-tunnel configuration, monitored end-to-end by a Wazuh SIEM. Covers agent management, File Integrity Monitoring, custom detection rule authoring (rule inheritance via `if_sid`), and a real, unplanned infrastructure incident — a disk-full condition that cascaded into API failures and database corruption risk — diagnosed and resolved from first principles.

**Key skills:** SIEM deployment, custom detection rules, Linux troubleshooting, root cause analysis, incident response.

See also: [OpenVPN Server Configuration](./OpenVPN_Wazuh_Project/OpenVPN-Server-Configuration.md) — verified ECDH curve (secp384r1), cipher suite, and split-tunnel design rationale.

### 2. [Simulated Network & Application-Layer Attack Detection](./Docker_Sim_Project/README.md)
Extension of the lab with a Docker host running OWASP Juice Shop, used to identify and close a real visibility gap — host-based monitoring has no native insight into containerized application traffic. Covers reverse proxy log collection, a custom detection rule for web attack patterns, and investigation of a rootcheck false positive.

**Key skills:** Docker deployment, SIEM visibility gap analysis, nginx reverse proxy logging, alert verification methodology.

### 3. [Attack Traffic Analysis: SQL Injection & File Upload RCE](./Docker_Sim_Project/dvwa-attack-traffic-analysis.md)
Hands-on offensive testing against DVWA (SQL injection, file upload to remote code execution), with all traffic captured and analyzed in Wireshark. Includes a full root-cause investigation of a TCP anomaly (Duplicate ACKs) that turned out to be a client-side artifact rather than a network or security issue — and honest documentation of a partial exploitation failure (extension handling) alongside the successful RCE chain.

**Key skills:** Manual web exploitation, packet analysis (Wireshark), SQL injection mechanics, detection-visibility awareness (GET vs. POST logging), root-cause investigation.

### 4. [Detecting C2 Beaconing: Custom Wazuh Detection Engineering](./C2_Detection/README.md)
A self-contained beacon simulator (Docker) used to generate realistic C2 check-in traffic, confirmed manually in Wireshark (consistent ~13s intervals, fixed 26-byte request size), then detected automatically via a custom multi-stage Wazuh decoder and frequency/timeframe correlation rule — built entirely from scratch, since no default Wazuh rule covers this behavior. Documents four separate, layered issues diagnosed in sequence (pre-decoder timestamp collision, a file that silently refused to save, missing field extraction blocking correlation, and an unrelated Hyper-V host disruption mid-session).

**Key skills:** Custom decoder authoring (multi-stage, regex field extraction), Wazuh frequency/timeframe correlation logic, `wazuh-logtest` for isolated rule diagnosis, systematic single-variable debugging, behavioral pattern detection vs. single-event detection.

## Recurring Themes Across These Projects

- **Real incidents, not staged ones.** The infrastructure problems documented here happened during genuine testing, not as scripted exercises — and are documented with the same rigor as the intended lab work.
- **Honest limitations, not just wins.** Where something didn't fully work as expected (POST body logging gaps, file extension mitigations, false positives), that's documented explicitly rather than omitted.
- **Detection and offense together.** Each offensive test is paired with an assessment of what a defender would (or wouldn't) see — tying attacker technique directly to detection engineering.

## Next Steps

- Additional custom Wazuh rules for command-injection and XSS traffic patterns
- Extended nginx logging to capture POST request bodies
- Cross-host correlation between network-layer (PCAP) and host-layer (Wazuh) evidence for the same attack timeline
- Additional vulnerable containers for lateral movement scenarios
- More realistic beacon jitter (percentage-based, larger range) and payload size variation, to test whether the current detection rule still holds
- DNS-tunneling detection as a follow-up to the C2 beaconing work, covering a different exfiltration/C2 channel than direct HTTP
