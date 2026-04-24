# Incident Report: UDP Scan Detection

## Summary
Snort rule sid:9000005 detected UDP traffic during live monitoring on interface
enp0s3. Alerts fired on legitimate DNS responses from the local gateway (10.0.2.3)
and QUIC traffic from external servers, revealing the rule was too broad for
production use.

## Detection Details
- **Rule:** `alert udp any any -> any any (msg:"UDP Scan Detected"; sid:9000005; rev:1;)`
- **SID:** 9000005
- **Interface:** enp0s3 (live network, not loopback)
- **Detection Time:** 2025-11-13 at 13:06:40

## What Was Observed
- `10.0.2.3:53 -> 10.0.2.15` — DNS replies from local gateway (normal traffic)
- `34.36.137.203:443 -> 10.0.2.15` — QUIC/UDP traffic from Google (normal traffic)
- No deliberate UDP attack simulation was captured in this log

## Key Learning
The rule `alert udp any any -> any any` matches ALL UDP traffic on the network,
including normal DNS lookups and browser traffic. In a real SOC environment this
would generate thousands of false positives per hour and make the rule useless.

A better rule would scope to a specific attack pattern, for example:
`alert udp any any -> any 161 (msg:"SNMP Probe"; sid:9000005; rev:2;)`

## Severity
**Informational** — No malicious UDP activity confirmed. Alerts were false positives
caused by an overly broad rule.

## Recommendations
- Narrow the rule to specific suspicious UDP ports (161, 1900, 5353)
- Add `detection_filter` to only alert after a volume threshold is exceeded
- Separate DNS monitoring into its own dedicated rule (sid:9000008)
