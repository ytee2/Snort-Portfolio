# Incident Report: TCP SYN Scan Detection

**Report ID:** YT-2025-001  
**Date:** September 24, 2025  
**Analyst:** Ytee 
**Severity:** Medium (Reconnaissance)  

## Executive Summary
A TCP SYN scan was detected targeting localhost (127.0.0.1) on September 18, 2025, at 07:18:12 UTC. This indicates potential port scanning activity, a common precursor to exploitation. Snort rule SID 9000004 triggered 1 alert. No exploitation observed; mitigated by passive monitoring. Recommendation: Block source IP if external.

## Detection Details
- **Tool:** Snort 3.1.82.0 in passive mode on lo interface.
- **Rule Triggered:** `alert tcp any any -> any any (msg:"TCP SYN scan detected"; flags:S; sid:9000004; rev:1;)`
- **Alert Time:** 09/24-2025 07:18:12.405977
- **Source:** 127.0.0.1:35511 (local test; in prod, external IP)
- **Destination:** 127.0.0.1:10180
- **Protocol:** TCP, SYN flag set, no ACK (DgmLen:44, Seq:0x95C6FA9A)

**Evidence (Snort Alert Excerpt):**
 [] [1:9000004:1] "TCP SYN scan detected" [] [Priority: 0] 09/21-07:18:12.405977 127.0.0.1:35511 -> 127.0.0.1:10180 TCP TTL:45 TOS:0x0 ID:43324 IpLen:20 DgmLen:44 *****S Seq: 0x95C6FA9A Ack: 0x0 Win: 0x400 TcpLen: 24 TCP Options
