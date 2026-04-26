# DNS Flood Detection with Snort 3

## Overview
Detect DNS floods via threshold on UDP queries to port 53. Uses detection_filter for rate limiting.

Tools: Snort 3.1.82.0, dig (in loop)

## Step 1: Rule Creation
Rule in local.rules:
alert udp any any -> any 53 (msg:"DNS Flood Detected"; detection_filter: track by_src, count 50, seconds 10; sid:9000008; rev:1;)

## Step 2: Snort Run
Command: sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A alert_full -k none -l /var/log/snort

## Step 3: Testing

 for i in {1..60}; do dig @127.0.0.1 evil.com; done

Alert Output: [**] [116:150:1] "(decode) loopback IP" [**]
[Priority: 3] 
09/22-10:41:03.745810 127.0.0.1:43762 -> 127.0.0.1:80
TCP TTL:64 TOS:0x0 ID:63365 IpLen:20 DgmLen:52 DF
***A**** Seq: 0xECB7F271  Ack: 0x462E6D11  Win: 0x200  TcpLen: 32
TCP Options (3) => NOP NOP TS: 4200925087 4200863646

 Screenshot: (Snort-Portfolio/Images/simulations/DNS/DNS_ping_alert.png)


## Key Takeaways
detection_filter prevents spam alerts. Tune count/seconds for sensitivity.


---

## Wireshark Analysis

### PCAP File
`logs/pcaps/dns_capture.pcap`

### What the Capture Shows
The PCAP contains 60+ rapid DNS queries all targeting the same domain
`evil.com`. This is the exact pattern produced by the parallel dig loop.

### Packet Breakdown
- All packets are DNS Standard Query Type A for `evil.com`
- Each query has a unique Transaction ID — confirming separate requests
- Multiple queries arrive within milliseconds of each other
- No DNS responses visible — 127.0.0.1 has no DNS server so queries go unanswered
- Packet timestamps show the flood completed in under 1 second

### What This Proves
Normal DNS behaviour involves one query followed by one response, then done.
The pattern here — 60 queries to the same domain with no responses, all
within milliseconds — is impossible in normal usage. This matches DNS flood
or subdomain enumeration behaviour. The unique transaction IDs per packet
confirm these are 60 separate deliberate queries, not retransmits of the
same query. This is exactly the traffic pattern Snort's `detection_filter`
threshold rule sid:9000008 is designed to catch.

### Screenshot
`Images/Intergrations/dns_wireshark.png`

## References
Snort Docs: https://www.snort.org/documents



