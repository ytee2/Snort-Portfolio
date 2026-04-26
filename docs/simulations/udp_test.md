# UDP Scan/Flood Detection with Snort 3

## Overview
Detect UDP scans/floods. Builds on TCP; tests connectionless protocol

Tools: Snort 3.1.82.0, nmap

## Step 1: Rule Creation
Rule in local.rules: alert udp any any -> any any (msg:"UDP Scan Detected"; sid:9000005; rev:1;)

## Step 2: Snort Run
Command: sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A alert_full -k none -l /var/log/snort

## Step 3: Testing
Test: nmap -sU localhost -p 1-1000

Alert Output: [**] [1:9000003:1] "ICMP any (bi)" [**]
[Priority: 0] 
09/22-06:50:38.355273 127.0.0.1 -> 127.0.0.1
ICMP TTL:64 TOS:0xC0 ID:44940 IpLen:20 DgmLen:56
Type:3  Code:3  DESTINATION UNREACHABLE: PORT UNREACHABLE
** ORIGINAL DATAGRAM DUMP:
127.0.0.1:57393 -> 127.0.0.1:204
UDP TTL:47 TOS:0x0 ID:23728 IpLen:20 DgmLen:28
Len: 0  Csum: 8414
** END OF DUMP

Screenshot: /Snort-Portfolio/Images/simulations/udp/ping_alert.png




## Key Takeaways
UDP rules are simple (no state). Add detection_filter for floods.

## References
Snort Docs: https://www.snort.org/documents


---

## Wireshark Analysis

### PCAP File
`logs/pcaps/udp_capture.pcap`

### What the Capture Shows
The PCAP contains rapid UDP packets sent from a single source to multiple
destination ports. This is the exact pattern produced by
`nmap -sU -p 1-100 127.0.0.1`.

### Packet Breakdown
- All packets originate from the same source port
- Destination ports change every packet — 94, 51, 6, 35, 36, 86 etc
- All packets are 42 bytes with 0 length payload — empty UDP probes
- No responses visible — all ports closed/filtered on loopback
- Multiple packets per second confirming automated scanning tool

### What This Proves
UDP has no handshake like TCP — an attacker simply sends a packet and
waits for a response. If a port is closed, the OS sends back an ICMP
Port Unreachable message. If there is no response, the port may be open
or filtered. The pattern of one source hitting dozens of ports in
milliseconds is impossible in normal usage and is the clear fingerprint
of an automated UDP scan. This is why broad UDP rules need thresholds —
without one, every UDP packet on the network would trigger an alert.

### Screenshot
`Images/Intergrations/udp_wireshark.png`


