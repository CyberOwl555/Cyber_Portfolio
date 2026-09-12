# BloodHound Active Directory Enumeration: Attack Path Analysis

## Overview

This project extends the Active Directory attack lab by deploying BloodHound — the industry-standard AD attack path analysis tool used by both red teams (to find exploitation routes) and blue teams (to find and eliminate them before attackers do). Where the previous AD project demonstrated executing attacks manually step by step, BloodHound automates the enumeration phase entirely, mapping every relationship in the domain as a graph and instantly surfacing attack paths that would take hours to find manually.

BloodHound answers the question every attacker asks after getting a foothold: **"What is the fastest path from this account to Domain Admin?"**

## What BloodHound Actually Does

BloodHound uses **graph theory** to model Active Directory relationships. Every user, group, computer, GPO, and OU becomes a node. Every relationship between them — group membership, ACL permissions, session data, trust relationships — becomes an edge. Once the graph is built, BloodHound can instantly calculate shortest paths between any two nodes using well-established graph algorithms.

The power is in what it finds that manual enumeration misses: multi-hop paths through unexpected relationships. A user might have GenericWrite on a group, which is nested in another group, which has WriteDACL on a computer, which has a Domain Admin session — a four-hop path that's invisible without the graph, but trivially obvious once it's visualised.

## Components

- **SharpHound** — the data collector. Runs on a domain-joined machine, queries Active Directory via LDAP, and dumps all relationship data as JSON files packaged in a zip. Collects: group memberships, local admin rights, sessions, ACLs, GPO links, object properties, trusts, SPN registrations.
- **BloodHound** — the graph analysis GUI. Ingests the SharpHound zip, builds the Neo4j graph database, and provides a query interface with dozens of pre-built attack path queries plus a raw Cypher query interface for custom analysis.
- **Neo4j** — the underlying graph database that stores and indexes the relationship data for fast path queries.

## Setup

- **BloodHound Legacy v4.3.1** installed on Windows 11 host
- **Neo4j Community 4.4.34** (BloodHound Legacy requires Neo4j 4.x — not compatible with 5.x)
- **Java 11** (OpenJDK, required by Neo4j)
- **SharpHound v2.5.9** — included in BloodHound's Collectors folder

**Note on Windows Defender:** BloodHound is correctly identified as a dual-use security tool and removed by Defender on download. A path exclusion was added for `C:\Tools` before downloading — standard practice for security research environments.

## Data Collection

SharpHound ran against `lab.local` authenticated as `jsmith` (a standard unprivileged domain user) — demonstrating that full AD enumeration requires nothing more than any valid domain account:

```powershell
.\SharpHound.exe -c All --domain lab.local --ldapusername jsmith --ldappassword Password123!
```

**Collection results:**
- 97 objects enumerated in 26 seconds
- Collection methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
- Output: `20260815163716_BloodHound.zip`

The fact that `jsmith` — an account with zero special privileges — can enumerate the entire domain's security relationships is itself a key finding. In a real engagement, an attacker needs only one valid credential (obtainable via password spray, phishing, or Kerberoasting) to map every attack path in the organisation.

## Findings

### Finding 1: Domain Admin Group Membership

The "Find all Domain Admins" query immediately shows `DOMAIN ADMINS@LAB.LOCAL` with its two members — `Administrator` and `sadmin`. For a defender, this view answers the question "who actually has Domain Admin?" instantly across a domain of any size, catching accounts that were added months ago and forgotten.

### Finding 2: svc_sql — Kerberoastable Account with High-Value Reach

The "List all Kerberoastable Accounts" query surfaced `SVC_SQL@LAB.LOCAL` alongside `KRBTGT@LAB.LOCAL`. The Node Info panel revealed several high-priority findings about this account:

- **Reachable High Value Targets: 9** — from `svc_sql`, BloodHound calculated 9 high-value targets reachable through relationship chains. A "just a service account" with this reach is a priority remediation target.
- **Password Last Changed: 14 Aug 2026** — in a real environment, service accounts often have passwords set once and never rotated, making the cracked hash valid indefinitely
- **Last Logon: Never** — a service account that has never logged in interactively is rarely monitored, making compromise less likely to be detected
- **SPN registered: MSSQLSvc/dc01.lab.local:1433** — explicitly marks this account as Kerberoastable

This directly corroborates the earlier Kerberoasting attack: BloodHound independently identified `svc_sql` as a priority target through static graph analysis, while the attack lab demonstrated the actual exploitation. The same account, found two different ways.


### Finding 3: Shortest Path to Domain Admins from svc_sql

The "Shortest Paths to Domain Admins" query with `svc_sql` as the starting node produced a rich attack path graph — the red highlighted path showing the calculated shortest route from the service account to domain admin level access, passing through DC01 and several intermediate relationships.

This is the core BloodHound use case: an attacker who Kerberoasted `svc_sql` and cracked its password now runs BloodHound to answer "what can I do with this?" The graph answers immediately, prioritising the most efficient path to full domain compromise.


## The Defensive Value

BloodHound is equally valuable as a defensive tool — arguably more so, since defenders can use it proactively to find and eliminate attack paths before they're exploited:

- **Find and remove unnecessary group nestings** that create unexpected privilege paths
- **Identify over-privileged service accounts** with reachable high-value targets
- **Prioritise remediation** — not all misconfigurations are equal, BloodHound shows which ones actually lead somewhere dangerous
- **Verify attack path elimination** — after remediation, re-run SharpHound and confirm the path no longer exists in the graph

In a real SOC/security team context, running BloodHound against your own domain periodically (or continuously with BloodHound Enterprise) is a standard part of AD security hygiene.

## Detection: Does BloodHound/SharpHound Leave Evidence?

Yes — SharpHound's LDAP queries generate Windows Event Log entries, specifically:

- **Event ID 4662** — Directory Service access events from the collecting machine
- **Event ID 4624** — Logon events for the account used to collect (jsmith in this case)
- Large volume of LDAP queries from a single source in a short window

Modern EDR solutions (CrowdStrike, SentinelOne) detect SharpHound by signature — it's a well-known tool. In a real red team engagement, operators use evasion techniques (renaming the binary, custom compilation, throttling queries) to avoid detection. For this lab, SharpHound ran unmodified — and in a production environment with Wazuh monitoring the DC, the burst of LDAP activity from `192.168.137.1` (the Windows 11 host) within the 26-second collection window would be visible in the event logs.

## Skills Demonstrated

- BloodHound/SharpHound deployment and operation
- Active Directory graph-based attack path analysis
- Identifying Kerberoastable accounts via BloodHound (corroborating manual Kerberoasting results)
- Understanding of graph theory applied to AD security relationships
- Defensive application of attack tooling (using attacker tools to find and eliminate paths)
- SharpHound detection awareness (Event ID 4662, LDAP query volume)
- Tool deployment in a restricted environment (Defender exclusions, Java PATH configuration)

## Limitations and Follow-Up Work

- The lab domain is small and clean — a real enterprise domain would show far more complex multi-hop paths, nested group misconfigurations, and ACL abuse opportunities
- No ACL misconfigurations were introduced — adding GenericWrite/WriteDACL relationships between accounts would demonstrate the most powerful BloodHound finding type (privilege escalation via ACL abuse)
- BloodHound Enterprise (the commercial version) provides continuous monitoring and quantifies attack path exposure as a metric — worth understanding as the enterprise deployment model
- SharpHound's detection footprint was not assessed against the Wazuh-monitored DC — a natural follow-up would be checking what Event ID 4662 activity the collection generated
