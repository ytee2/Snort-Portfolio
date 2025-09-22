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





