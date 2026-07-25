# OpenVPN Server Configuration — Split-Tunnel VPN

## Purpose
Self-hosted OpenVPN server providing a split-tunnel connection between a Windows 11 host and a dedicated Ubuntu Server 24.04 VM, used as the foundation for the broader Wazuh SIEM monitoring project (see: Home Lab SIEM Deployment write-up).

## Configuration

```
port 1194
proto udp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh none
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
```

## Key Configuration Decisions

- **Protocol/Port:** UDP on 1194 (OpenVPN default) — UDP chosen over TCP for lower latency and to avoid "TCP meltdown" (performance degradation when tunneling TCP traffic inside another TCP connection).
- **Key exchange:** `dh none` — no static Diffie-Hellman parameters file is used. Instead, key exchange is handled via the TLS handshake itself using Elliptic Curve Diffie-Hellman (ECDH). Verified directly against the server certificate (`openssl x509 -in server.crt -text -noout`): the certificate uses `id-ecPublicKey` with a 384-bit key, confirming the **secp384r1 (P-384)** curve — a NIST curve offering a higher security margin than the more commonly deployed secp256r1 (P-256), at a modest performance cost. This is the modern, recommended approach over legacy static DH, avoiding both the computational overhead and periodic regeneration that static DH parameters require.
- **Cipher:** AES-256-GCM — an authenticated encryption cipher (AEAD), providing both confidentiality and integrity in a single operation, rather than requiring a separate HMAC step.
- **Auth digest:** SHA256 — used for the TLS control channel authentication.
- **Privilege dropping:** `user nobody` / `group nogroup` — the OpenVPN process drops root privileges after initialization, limiting the blast radius if the process were ever compromised.
- **Persistence flags:** `persist-key` / `persist-tun` — prevents the server from re-reading key files or closing/reopening the tun device on restart, avoiding unnecessary privilege re-escalation.

## Split-Tunnel Design

Unlike a full-tunnel VPN (where all client traffic routes through the server), this configuration only routes specifically defined traffic between the Windows host and the VPN server through the tunnel — general internet traffic on the Windows host continues to use its normal default route. This was a deliberate architectural choice: the goal of this project was to demonstrate secure point-to-point connectivity and VPN server administration, not to provide full internet gateway functionality (that would be a distinct project — see "Next Steps" in the main SIEM write-up for notes on what a full-tunnel gateway reconfiguration would require).

## Verification Performed

- Confirmed OpenVPN service active and accepting connections (`systemctl status openvpn-server@server`)
- Confirmed successful client connection from Windows 11 host via the OpenVPN client
- Confirmed traffic routed through the tunnel only for explicitly configured routes, with general internet traffic unaffected
- Config directory (`/etc/openvpn`) brought under Wazuh File Integrity Monitoring with realtime detection enabled, with a custom high-severity detection rule (rule ID 100010/100011) specifically for changes to this configuration — see the SIEM deployment write-up for full detail

## Notes / Housekeeping

- A stray test artifact (`# test comment`) was left in this config from earlier FIM testing (deliberately triggering a file-change alert) — harmless (a comment line, not active configuration) but should be removed for a clean production-style reference config.
