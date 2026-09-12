# Detecting DNS Tunneling: Decoder Engineering and Multi-Tier Alert Escalation

## Overview

This project simulates DNS tunneling — a technique used by attackers to exfiltrate data or maintain C2 communications by encoding information into DNS query subdomains, exploiting the near-universal permissiveness of DNS traffic through firewalls. A working detection was built in Wazuh from scratch, requiring a two-stage custom decoder (prematch + regex field extraction) and a three-tier rule chain escalating from individual suspicious queries to high-volume exfiltration alerts.

This project directly follows and complements the C2 beaconing detection project: where beaconing detection focused on *timing patterns* (frequency/timeframe correlation), DNS tunneling detection focuses on *content structure* (query name characteristics, field extraction, volume escalation) — a meaningfully different detection approach for a different attacker technique.

## Why DNS Tunneling Is Particularly Dangerous

DNS is almost never blocked at the network perimeter — doing so breaks essentially everything, since every internet connection starts with a DNS lookup. This makes it an attractive covert channel: an attacker who can reach a DNS server (their own, configured as authoritative for a domain they control) can send and receive arbitrary data disguised as completely ordinary-looking DNS queries, even through corporate firewalls and proxies that block everything else.

The data is encoded into subdomain labels: instead of querying `mail.google.com`, a tunneling tool might query `OVZWK4R5MFSG22LOHNYGC43THVJXK4DF.attacker.com` — with the long, high-entropy label actually being base32-encoded stolen credentials, a command, or a file chunk. The DNS server on the attacker's end decodes the subdomain and reassembles the data. To a firewall, it's just DNS traffic.

## Architecture

- **tunnel-server**: a Python UDP server (Docker container) that receives DNS queries, decodes the base32-encoded subdomain labels back into the original data, logs each event, and returns a harmless `127.0.0.1` response so the client's request completes cleanly
- **tunnel-client**: a Python script (Docker container) that encodes simulated sensitive data into base32, splits it into DNS-label-sized chunks, and transmits each chunk as a genuine DNS wire-format query (using the `dnslib` library) to the server every 6 seconds
- Both containers run on a dedicated Docker network (`dnstunnel-net`), isolated from other lab traffic
- The server's query log is volume-mounted to the Docker host filesystem for Wazuh agent monitoring

**Simulated exfiltrated data:**
```
user=admin;pass=SuperSecret123;host=internal-db-01;token=eyJhbGciOiJIUzI1NiJ9
```
This is encoded into base32, split across four DNS queries, and transmitted in a continuous loop — mimicking real-world data exfiltration via DNS tunnel.

## Phase 1: Confirming the Signature in Wireshark

Traffic was captured on the correct bridge interface (`br-xxxxxxxxxxxx` for the custom Docker network rather than `docker0`, which is only the default bridge) and analyzed in Wireshark.

**Key observations:**

**Query name length:** `[Name Length: 53]` displayed automatically by Wireshark — a typical legitimate DNS query (`mail.google.com`, `cdn1.cloudflare.com`) runs roughly 14-20 characters. A 53-character name is immediately anomalous and directly thresholdable in a detection rule.

**Label composition:** the encoded label `HN2G623FNY6WK6KKNBREOY3JJ5UUUSKVPJETCTTJ` is 40 uppercase alphanumeric characters with no vowels, no word structure, and no resemblance to any human-generated subdomain. This is the high-entropy signature that distinguishes tunneled data from legitimate subdomains.

**Repetition pattern:** the same 3-4 base domain (`tunnel.local`) appears in every single query, cycling through the same encoded chunks continuously. Real domains receive occasional, varied lookups from many sources; a tunnel destination receives constant, predictable, same-source queries.

**Protocol classification:** Wireshark classified traffic as MDNS rather than DNS because port 5353 (standard mDNS port) was used rather than port 53. In a real environment, DNS tunneling on non-standard ports is itself an additional detection signal — legitimate DNS uses port 53.

**Capture artifact investigation:** initial captures using `tcpdump -i any` showed apparent duplicate frames with identical transaction IDs and timestamps. Investigation confirmed these were capture-side artifacts — a single packet being recorded at two points in Docker's virtual network path rather than genuine retransmissions or transaction ID collisions. Confirmed by recapturing on the specific bridge interface, whereupon the duplicates disappeared entirely. **Lesson: `-i any` is convenient but can produce misleading artifacts in virtualized/containerized environments; specific interface targeting is more reliable for accurate analysis.**


## Phase 2: Building the Detection

### Decoder Design — Two-Stage Architecture

A single-stage prematch decoder is insufficient here because the detection rules need to operate on specific *fields* (the query name, the source IP) rather than just the presence of a matching string. This required a two-stage decoder:

**Stage 1 — prematch (identifies the log source):**
```xml
<decoder name="dnstunnel">
  <prematch>dnstunnel: query</prematch>
</decoder>
```

**Stage 2 — child decoder (extracts structured fields):**
```xml
<decoder name="dnstunnel">
  <parent>dnstunnel</parent>
  <regex>qname=(\S+) decoded=(\S+) src=(\S+)</regex>
  <order>dns.query, extra_data, srcip</order>
</decoder>
```

**Key design decision — `\S+` not `.+` for the decoded field:** an initial attempt used `.+` (match any character, greedy) for the decoded value capture group. This caused the regex to fail entirely: `.+` consumed the rest of the line including `src=172.19.0.3`, leaving nothing for the final capture group to match, so the whole regex returned no match. Switching to `\S+` (non-whitespace characters only) correctly stops at the space before `src=`, since the decoded values in this log format are semicolon-delimited with no embedded spaces.

**Diagnosed using `wazuh-logtest`** — Wazuh's built-in interactive decoder/rule testing tool, which processes a single log line through the full decoding and rule pipeline without touching live traffic. This was also the tool that confirmed the base prematch was working but the child decoder wasn't extracting fields, isolating the problem to the regex specifically rather than the decoder architecture.

**Note on `wazuh-logtest` input handling:** the tool reads one line per Enter press from stdin. When pasting a long line interactively, some terminal emulators break it at spaces, sending it as multiple separate lines. Workaround: pipe input via a temp file (`sudo /var/ossec/bin/wazuh-logtest < /tmp/testline.txt`) to ensure the full line is sent as a single unit.

### Three-Tier Rule Chain

```xml
<group name="local,dns,tunnel,">

  <rule id="100040" level="3">
    <decoded_as>dnstunnel</decoded_as>
    <match>dnstunnel: query</match>
    <description>DNS query observed via tunnel simulator</description>
    <group>dns_query,</group>
  </rule>

  <rule id="100041" level="10">
    <if_sid>100040</if_sid>
    <field name="dns.query">\.tunnel\.local</field>
    <description>Suspicious DNS query to tunnel.local domain - possible DNS tunneling</description>
    <group>dns_tunnel,</group>
  </rule>

  <rule id="100042" level="12" frequency="10" timeframe="60">
    <if_matched_sid>100041</if_matched_sid>
    <same_source_ip />
    <description>High volume DNS queries to tunnel domain - DNS tunneling likely</description>
    <group>dns_tunnel,exfiltration,</group>
  </rule>

</group>
```

**Tier rationale:**
- **100040 (level 3):** base catch — any event from the dnstunnel decoder. Low severity since any individual DNS query, even an unusual one, is low signal on its own.
- **100041 (level 10):** narrows to queries specifically targeting the tunnel domain, using the `dns.query` field extracted by the child decoder. This is meaningful enough to be worth an alert — a suspiciously-named query to a specific domain is no longer ambient noise.
- **100042 (level 12):** escalation — 10+ queries to the same domain from the same source within 60 seconds. This is the pattern-level detection, where the *volume* confirms this is systematic exfiltration rather than a single anomalous lookup. The `previous_output` field in the alert shows the full list of preceding events that triggered the escalation.


## Most Significant Finding

The `previous_output` field in rule 100042's alert detail contains the actual reconstructed data fragments from the DNS queries — including `decoded=user=admin;pass=SuperSecr` visible in plaintext in the SIEM alert. This directly illustrates the threat: an analyst reviewing this alert sees not just "suspicious DNS activity occurred" but the actual content being exfiltrated, reconstructed by the SIEM from what looked like routine DNS queries to network-layer monitoring.

## Skills Demonstrated

- Two-stage Wazuh decoder design (prematch identification + child regex field extraction)
- Regex debugging in a log-parsing context — specifically understanding greedy vs. non-greedy capture group behavior (`\S+` vs `.+`) and how to diagnose it via wazuh-logtest
- Three-tier rule escalation chain: catch-all → domain-specific → volume/pattern escalation
- `wazuh-logtest` proficiency including non-interactive input for reliable testing of multi-word log lines
- Wireshark analysis on containerized traffic including correct interface selection for Docker custom networks
- Capture artifact identification (tcpdump `-i any` double-capture on virtual network paths)
- Contrasting detection approaches: timing-based (beaconing) vs. content/structure-based (DNS tunneling) — different techniques require different detection strategies

## Limitations and Follow-Up Work

- Detection currently relies on the domain suffix `tunnel.local` being identifiable — real attackers use legitimate-looking domains they control, so domain-based matching alone would miss most real tunneling. A production detection would add query length thresholding (flag any subdomain label over ~30 characters) and entropy-based scoring, neither of which Wazuh's native rule syntax supports directly without external processing.
- Only direct UDP DNS queries were simulated — HTTPS-based DNS (DoH) and DNS-over-TLS (DoT) are increasingly common and would bypass this detection entirely, since the query content is encrypted.
- The `\S+` fix for the decoded field means log lines where the decoded value contains spaces would silently fail field extraction — acceptable for this simulator but worth noting as a fragility if the log format ever changes.
