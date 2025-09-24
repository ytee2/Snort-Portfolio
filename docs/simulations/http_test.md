# HTTP Directory Traversal Detection with Snort 3

## Overview
Detect basic HTTP attacks like directory traversal. Tests app-layer content matching.

Tools: Snort 3.1.82.0, curl

## Step 1: Rule Creation
Rule in local.rules: alert tcp any any -> any 80 (msg:"HTTP Directory Traversal Detected"; content:"../"; http_uri; sid:9000006; rev:1;)

## Step 2: Snort Run
Command: sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A alert_full -k none -l /var/log/snort

## Step 3: Testing
Test: curl "http://localhost/../etc/passwd" (with python3 -m http.server 80 running)

Alert Output: 
[**] [116:150:1] "(decode) loopback IP" [**]
[Priority: 3] 
09/22-09:33:20.514548 127.0.0.1:80 -> 127.0.0.1:43762
TCP TTL:64 TOS:0x0 ID:44637 IpLen:20 DgmLen:52 DF
***A**** Seq: 0x462E6D11  Ack: 0xECB7F272  Win: 0x1FF  TcpLen: 32
TCP Options (3) => NOP NOP TS: 4196861856 4196369832

Screenshot:![Snort Startup Output] Snort-Portfolio/Images/simulations/http/http_ping_alert.png

## Key Takeaways
Use http_uri for normalized URI checks. Add nocase for case-insensitivity.

## References
Snort Docs: https://www.snort.org/documents
