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

### 5. [Detecting DNS Tunneling: Decoder Engineering and Multi-Tier Alert Escalation](./DNS_Tunnelling/README.md)

Simulation of DNS tunneling — encoding stolen credentials into base32-encoded DNS subdomain labels and transmitting them as genuine DNS wire-format packets using dnslib — with a three-tier Wazuh detection rule chain (individual query catch → domain-specific detection → high-volume escalation) and a two-stage custom decoder to extract structured fields. Includes Wireshark analysis confirming the tunneling signature (53-character query names, high-entropy encoded labels, repetitive same-destination query pattern), investigation of a capture artifact caused by tcpdump -i any on a containerised network, and decoder debugging via regex fix (greedy .+ → non-greedy \S+). The level 12 escalation alert surfaces the actual decoded exfiltrated data (credentials) directly in the alert's previous_output field.

Key skills: DNS protocol and tunneling mechanics, two-stage decoder design, regex field extraction debugging, three-tier rule escalation (catch-all → content-specific → volume pattern), Wireshark analysis on Docker bridge networks, capture artifact identification and investigation.

### 6. [Lateral Movement Detection: Web Shell Execution to Persistence — Attack Chain Correlation](./Lateral_Movement/README.md)

Full post-exploitation attack chain simulation — initial access via web shell RCE, host/network enumeration, lateral pivot to a second container, and persistence file drop — across a multi-container Docker environment, with Wazuh detection covering each stage. Includes resolving a third instance of the recurring container log visibility gap (Apache logs volume-mounted to host filesystem), discovering and building on Wazuh's built-in web shell rule (31514, with full MITRE ATT&CK and compliance mappings) rather than duplicating its logic, and a frequency/timeframe correlation rule (level 14, mail: True) that escalates multiple web shell commands from the same source into a confirmed attack chain alert. The final alert's previous_output field shows the exact command sequence that triggered escalation. All detections fired against a live, noisy background of simultaneously running DNS tunnel and C2 beacon simulators from earlier projects.

### 7. [Suricata Network IDS: Closing the Network Visibility Gap](./Suricata/README.md)

Deployment of Suricata as a network-based IDS on the Docker host, monitoring all three Docker bridge interfaces simultaneously — directly addressing the blind spot identified in project 6 where container-to-container lateral movement generated no Wazuh alert. The Emerging Threats Open ruleset (52,238 signatures) immediately detected the C2 beacon simulator via the Python BaseHTTP server response banner, providing independent network-level corroboration of the same activity already being caught by Wazuh's log-correlation rules — demonstrating the defence-in-depth value of combining host-based and network-based detection. Suricata's structured eve.json output is ingested by the existing Wazuh agent, unifying host and network alerts in a single dashboard. Includes honest documentation of what Suricata still missed (the pivot TCP connection) and why, with a follow-up path to custom rule writing.

Key skills: Network IDS deployment and configuration, multi-interface packet capture (af-packet), Emerging Threats community ruleset management, eve.json Wazuh integration, host-based vs. network-based detection paradigm comparison, cross-detection corroboration (same attack caught by two independent mechanisms), scalability mapping from lab to enterprise deployment.

Key skills: Attack chain simulation and correlation, container log architecture (volume mounts for agent visibility), built-in rule discovery before custom authoring, frequency/timeframe correlation with same_source_ip, FIM-based persistence detection, Docker networking diagnostics, operating in a noisy multi-alert environment.

### 8. [Active Directory Attack Lab: Kerberoasting, Password Spraying, Credential Dumping, and Pass-the-Hash](./Active_Directory_Attack/README.md)

A purpose-built Active Directory environment (Windows Server 2019 Core domain controller, Kali Linux attack machine, domain-joined Windows 11 workstation) used to execute and detect a complete post-exploitation attack chain directly relevant to SANS SEC504. Starting with a single unprivileged domain user account, the full chain runs: Kerberoasting (svc_sql TGS hash extracted and cracked offline) → password spraying (Domain Admin sadmin compromised with zero lockouts) → credential dumping (all domain NTLM hashes extracted via DCSync including krbtgt) → Pass-the-Hash (SYSTEM shell on the DC using only the Administrator hash, no password). Every stage monitored by Wazuh with Windows audit logging enabled — Event ID 4769 with RC4 encryption type 0x17 (Kerberoasting), 4625 failures and 4624 success (password spray), 4624 Type 3 NTLM from unexpected source (Pass-the-Hash) — all firing automatically with MITRE ATT&CK tags. Total time from first attack to SYSTEM: approximately 10 minutes from one standard domain user account.

Key skills: Active Directory deployment and administration (Server Core), Kerberoasting and offline hash cracking, password spraying with lockout-safe tooling (NetExec), DCSync credential dumping (Impacket secretsdump), Pass-the-Hash lateral movement (psexec), Windows audit policy configuration, Windows Security Event Log analysis (4624/4625/4769), MITRE ATT&CK mapping (T1558.003/T1110.003/T1003.002/T1550.002), PICERL incident response framework application.

### 9. [BloodHound AD Enumeration: Attack Path Analysis](./BloodHound_Enumeration/README.md)
BloodHound deployed against the existing lab.local Active Directory environment to map every domain relationship as a graph and surface attack paths automatically. SharpHound collected 97 objects in 26 seconds authenticated as jsmith (unprivileged standard user) — demonstrating that full domain enumeration requires only one valid credential. Key findings: svc_sql Kerberoastable account identified with 9 reachable high-value targets and Last Logon: Never (corroborating the manual Kerberoasting result from project 8 through independent graph analysis), Domain Admin membership visualised, and shortest attack path from svc_sql to Domain Admins rendered as a graph with the red highlighted route. Covers both offensive application (finding attack paths) and defensive application (eliminating paths before attackers find them).

Key skills: BloodHound/SharpHound deployment and operation, AD graph-based attack path analysis, Kerberoastable account identification, graph theory applied to AD security, defensive use of attack tooling, SharpHound detection awareness (Event ID 4662, LDAP query volume).


## Recurring Themes Across These Projects

- **Real incidents, not staged ones.** The infrastructure problems documented here happened during genuine testing, not as scripted exercises — and are documented with the same rigor as the intended lab work.
- **Honest limitations, not just wins.** Where something didn't fully work as expected (POST body logging gaps, file extension mitigations, false positives), that's documented explicitly rather than omitted.
- **Detection and offense together.** Each offensive test is paired with an assessment of what a defender would (or wouldn't) see — tying attacker technique directly to detection engineering.
- **Visibility gaps as a recurring theme. Container log visibility has come up in three separate projects and been resolved three different ways — a pattern that demonstrates genuine depth of understanding of a core SIEM      architectural constraint rather than a single lucky fix.
- **Speed of compromise. The AD attack chain demonstrates total domain compromise in under 10 minutes from a single unprivileged user account — reinforcing why detection and response speed matters more than perimeter          defence alone.

## Next Steps

- Golden Ticket attack demonstration — using the captured krbtgt hash to forge persistent domain admin access

- ACL abuse misconfigurations — add GenericWrite/WriteDACL relationships to the lab domain to demonstrate more complex multi-hop BloodHound attack paths

- AD Certificate Services (ADCS) attacks — ESC1/ESC8 certificate template abuse, a major attack surface SEC504 covers

- Memory forensics basics using Volatility against a memory dump from the DC

- PICERL incident response documentation — formally applying the incident handling framework to the disk-full cascading failure from project 1

- Custom Suricata rule for container-to-container pivot detection — closing the specific gap identified in project 7

- SSH honeypot (Cowrie) to capture real attacker behaviour and feed into Wazuh

 ## Tools and Approach
Lab infrastructure built and managed via Hyper-V, Docker, and Ubuntu Server.
Detection engineering performed in Wazuh 4.8.2 with Suricata 8.0.6.
Traffic analysis via Wireshark and tcpdump. AI assistance (Claude) used
for syntax reference and debugging support during development, with all
detection logic, troubleshooting methodology, and analysis performed
and verified manually.

