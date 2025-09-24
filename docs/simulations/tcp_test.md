# TCP SYN Scan Detection with Snort 3

## Overview
Detect TCP SYN scans using a custom Snort rule. Tests show passive mode on eth0 misses local outgoing traffic; use loopback or incoming scans.

Tools: Snort 3.1.82.0, nmap, tcpdump.

## Step 1: Rule Creation
Rule in local.rules for SYN-only packets.

Rule: alert tcp any any -> any any (msg:"TCP SYN scan detected"; flags:S; sid:9000004; rev:1;)

## Step 2: Snort Configuration and Run
Command:sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A alert_full -k none -l /var/log/snort
-i lo: Captures local traffic.
-A alert_full: Outputs alerts to terminal.

Screenshot: Snort-Portfolio/Images/simulations/tcp/snort_startup.png

## Step 3: Testing the Rule
Test Command: nmap -sS localhost

Alert Output: [**] [1:9000004:1] "TCP SYN scan detected" [**]
[Priority: 0] 
09/21-07:18:12.405977 127.0.0.1:35511 -> 127.0.0.1:10180
TCP TTL:45 TOS:0x0 ID:43324 IpLen:20 DgmLen:44
******S* Seq: 0x95C6FA9A  Ack: 0x0  Win: 0x400  TcpLen: 24
TCP Options (1) => MSS: 1460

Screenshot:/Snort-Portfolio/Images/simulations/tcp/ping_alert.png




## Key Takeaways
Rules need traffic direction and interface checks.
Test config: sudo snort -T -c /etc/snort/snort.lua -R local.rules
Add thresholds for production to reduce spam.

## References
Snort Docs: https://www.snort.org/documents
GitHub Repo: https://github.com/Ytee2]




