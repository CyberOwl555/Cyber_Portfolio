# Detecting C2 Beaconing: Custom Wazuh Detection Engineering

## Overview

This project simulates a core technique used by real command-and-control (C2) malware — periodic "beaconing" check-ins to a remote server — and builds a working Wazuh detection for it from scratch. Unlike the earlier projects in this lab, which largely relied on Wazuh's built-in rules or straightforward extensions of them, this project required writing a custom decoder, extracting structured fields from raw log text, and using Wazuh's frequency/correlation logic to distinguish a *behavioral pattern* (repeated beaconing) from a single low-signal event.

The exercise also served as a genuine, unplanned lesson in layered troubleshooting — four separate, independent problems had to be diagnosed and resolved in sequence before the detection worked, each requiring a different diagnostic approach.

## Objective

Build a lightweight, self-contained beacon simulator, capture its traffic, confirm the behavioral signature (regular timing, consistent packet size) in Wireshark, then build and validate a Wazuh detection rule that identifies the pattern automatically — without relying on Wazuh's default rule set, since no out-of-the-box rule exists for this behavior.

## Architecture

- **c2-sim-server**: a minimal Python HTTP server (Docker container) that logs every check-in it receives to a file
- **c2-sim-client (beacon)**: a Python script (separate Docker container) that "checks in" to the server on a randomized interval (15 seconds ± 3 seconds jitter), mimicking real malware beaconing behavior
- Both containers run on a dedicated Docker network (`c2sim-net`) on the existing Docker host, alongside the Juice Shop and DVWA targets from earlier projects
- The server's check-in log is volume-mounted to the host filesystem, where the Wazuh agent monitors it directly

```python
# Simplified beacon logic
while True:
    send_checkin_request()
    sleep(BASE_INTERVAL + random.uniform(-JITTER, JITTER))
```

**Design note:** this is a deliberately simplified model. Real C2 frameworks use much more aggressive jitter (often percentage-based, e.g. ±50% of sleep time), vary request/packet size to avoid a consistent size signature, and increasingly employ domain fronting or legitimate-service traffic blending to avoid destination-based detection entirely. This simulator isolates and demonstrates the *timing* signature specifically, as a foundation for understanding the broader detection problem — not a full replication of real-world evasion sophistication.

## Phase 1: Confirming the Behavioral Signature Manually

Before building any automated detection, the traffic was captured (`tcpdump`) and analyzed in Wireshark to confirm the pattern was actually detectable by a human analyst first.

**Findings:**
- Every check-in request was **26 bytes**, with zero variation across dozens of samples
- Inter-request intervals clustered tightly around **13 seconds**, consistent with the configured 15±3 second jitter window

This consistency — in both size and timing — is the core signature that distinguishes beaconing from normal application traffic, which is characteristically bursty and irregular (multiple requests fire together on page load, then nothing until the next user action). A metronomic, single-request, fixed-size pattern repeating indefinitely has no legitimate equivalent in typical human-driven browsing.

*[Screenshot: Wireshark packet list showing consistent ~13s intervals and 26-byte request size]*

## Phase 2: Building the Detection — Four Issues, Diagnosed in Sequence

### Issue 1: Decoder failed to match due to log format ordering
The initial log format placed an ISO 8601 timestamp before the log identifier:
```
2026-07-26T10:10:22.558185 c2sim: checkin src=172.18.0.3 path=/checkin
```
Wazuh's pre-decoding stage attempts to auto-detect a timestamp at the start of every line. It misparsed this format, consuming part of the line (including the start of "c2sim") into a malformed timestamp field and leaving nothing for the custom decoder to match against — resulting in "No decoder matched," despite correct decoder syntax.

**Diagnosis method:** `wazuh-logtest`, Wazuh's built-in interactive rule/decoder testing tool, which processes a single log line through the full decoding and rule pipeline and reports exactly which stage succeeded or failed — without needing to wait on live traffic or dig through the dashboard.

**Fix:** reordered the log format so the identifier comes first:
```
c2sim: checkin timestamp=2026-07-26T10:10:22.558185 src=172.18.0.3 path=/checkin
```

### Issue 2: A source file silently stopped accepting writes
While applying the fix above, repeated attempts to overwrite the Python script via a heredoc (`cat > file << 'EOF'`) executed without error but left the file's content and modification timestamp unchanged. Ownership and permissions were confirmed normal (`ls -la`), ruling out an access issue.

**Diagnosis method:** wrote the same content to a brand-new filename to isolate whether the *mechanism* (heredoc) or the *specific file* was at fault. The new file wrote correctly, confirming the original file itself — not the write method — was the problem.

**Fix:** deleted the unresponsive file and renamed the working replacement into place, rather than continuing to investigate the underlying cause of the stuck file, since a reliable workaround was faster than root-causing an edge case with no further diagnostic value.

### Issue 3: Base rule confirmed working, correlation rule still silent
With the log format fixed, the base detection rule (matching individual check-ins) was confirmed firing correctly via `wazuh-logtest`. However, the intended pattern-detection rule — using Wazuh's `frequency`/`timeframe` correlation with `<same_source_ip />` — still did not fire, even in a controlled manual test simulating five rapid check-ins from the same source.

**Root cause:** the decoder only performed a `prematch` (confirmed the expected text was present in the line) but never extracted any structured fields from it. `<same_source_ip />` requires a `srcip` field to exist in the decoded event to correlate against — with no field extraction, there was nothing for it to compare.

**Fix:** added a second, child decoder stage using a regex to extract the source IP and request path into named fields:
```xml
<decoder name="c2sim">
  <prematch>c2sim: checkin</prematch>
</decoder>

<decoder name="c2sim">
  <parent>c2sim</parent>
  <regex>src=(\S+) path=(\S+)</regex>
  <order>srcip, url</order>
</decoder>
```

### Issue 4: Infrastructure disruption during the debugging session
Separately, a Hyper-V host memory exhaustion issue (unrelated to this project, caused by an orphaned virtual machine worker process) required a full host reboot mid-session, which briefly disrupted Docker networking and required re-verifying container and agent connectivity before troubleshooting could safely continue. This is noted here because it's a realistic complication: production troubleshooting rarely happens in a perfectly isolated, single-variable environment, and separating "is this new problem related to what I'm debugging, or is it environmental noise" is itself part of the skill.

## Final Working Detection Rules

```xml
<group name="local,c2,beaconing,">

  <rule id="100030" level="3">
    <decoded_as>c2sim</decoded_as>
    <match>checkin</match>
    <description>C2 simulator check-in observed</description>
    <group>c2_checkin,</group>
  </rule>

  <rule id="100031" level="12" frequency="5" timeframe="90">
    <if_matched_sid>100030</if_matched_sid>
    <same_source_ip />
    <description>Possible C2 beaconing: 5+ check-ins from same source within 90 seconds</description>
    <group>c2_beaconing,</group>
  </rule>

</group>
```

**Design rationale:** Rule 100030 is intentionally low-severity (level 3) — a single check-in event is not inherently suspicious on its own and would generate excessive noise if treated as an alert-worthy event. Rule 100031 is where the actual detection value lives: it uses Wazuh's `frequency` and `timeframe` correlation to require **5 or more matching events from the same source within a 90-second window** before escalating to a high-severity (level 12) alert. This directly encodes the manually-observed timing signature from Phase 1 into an automated, reusable detection — the rule fires on the *pattern*, not the individual event.


## Skills Demonstrated

- Writing a multi-stage custom Wazuh decoder (base `prematch` + child regex field extraction), not just chaining off existing decoders
- Using Wazuh's frequency/timeframe correlation logic to detect a behavioral pattern rather than a single event
- Systematic, single-variable-at-a-time debugging across four distinct, layered failures
- Correct use of `wazuh-logtest` as a rapid, isolated diagnostic tool — bypassing the live agent-to-manager pipeline entirely to test decoder/rule logic directly
- Manual packet analysis to confirm a detectable behavioral signature (timing regularity, size consistency) before building automated detection around it
- Recognizing and correctly separating unrelated environmental disruption (the Hyper-V/host reboot) from the actual problem under investigation, rather than conflating the two

## Honest Limitations / Follow-Up Work

- This simulator's jitter (±3 seconds on a 15-second base) is far less sophisticated than real C2 frameworks, which typically use larger, percentage-based jitter and vary payload size to avoid exactly this kind of size/timing fingerprinting
- The detection rule currently correlates purely on source IP and frequency; a production-grade version would likely also incorporate destination reputation, longer observation windows (hours/days, to catch low-and-slow beaconing), and statistical variance analysis rather than a fixed count/window threshold
- No DNS-based or domain-fronted beaconing was tested — this detection is specific to direct HTTP beaconing over a known port
