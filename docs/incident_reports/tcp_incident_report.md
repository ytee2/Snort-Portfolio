# Incident Report: TCP SYN Scan Detection

## Summary
Snort detected TCP SYN packets originating from this machine (10.0.2.15) targeting
multiple ports on external hosts. The pattern is consistent with an nmap SYN scan
run during simulation testing.

## Detection Details
- **Rule:** `alert tcp any any -> any any (msg:"TCP SYN scan detected"; flags:S; sid:9000004; rev:1;)`
- **SID:** 9000004
- **Interface:** enp0s3
- **Detection Time:** 2025-11-13 at 17:58:44

## What Was Observed
- Source: `10.0.2.15` (this machine)
- Targets: `23.220.75.245` and `23.192.228.80`
- Ports probed: 443, 80, 22, 135, 111, 256, 53 — multiple different ports
- All packets are SYN-only (no ACK), confirming half-open scan technique
- Activity spans from 17:58:44 to 17:59:06 — about 22 seconds total

## Why This Confirms a SYN Scan
In a normal TCP connection, packets go SYN → SYN-ACK → ACK (the three-way
handshake). A SYN scan sends ONLY the first SYN packet to each port and never
completes the handshake. The `flags:S` in the rule matches exactly this —
packets with ONLY the SYN flag set. Seeing SYN packets to 7+ different ports
in 22 seconds from one source confirms scanning behaviour.

## Severity
**Medium** — Reconnaissance activity. No exploitation occurred but the scan
reveals which ports are open, which an attacker would use to plan next steps.

## Limitations Noted
This rule also catches normal outbound connections from the machine, since every
TCP connection starts with a SYN. A more precise rule would combine the SYN flag
check with a `detection_filter` to only alert when many SYN packets are sent in
a short window.

## Recommendations
- Add threshold: `detection_filter: track by_src, count 20, seconds 5;`
- Correlate with ICMP alerts from same source — SYN scan usually follows ping sweep
- Monitor destination ports — scanning common ports (22, 80, 443) is high priority
