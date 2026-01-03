# TCP SYN Scan Detection with Snort 3

## Overview
This simulation demonstrates detection and investigation of a TCP SYN scan using
Snort 3 and Kibana. TCP SYN scans are a common reconnaissance technique used by
attackers to identify open ports and listening services prior to exploitation.

---

## Tools Used
- Snort 3.1.82.0
- Nmap
- ELK Stack (Elasticsearch, Logstash, Kibana)

---

## Step 1: Rule Creation
A custom Snort rule was created to detect TCP packets with only the SYN flag set,
indicating a potential port scan.

Rule:
alert tcp any any -> any any (msg:"TCP SYN scan detected"; flags:S; sid:9000004; rev:1;)

yaml
Copy code

---

## Step 2: Start Snort IDS
Snort was started in IDS mode on the loopback interface to capture local test traffic.

Command:
sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A fast -l /var/log/snort -v

yaml
Copy code

📸 Screenshot Purpose:  
`snort_startup.png` shows Snort running successfully with rules loaded and monitoring traffic.

---

## Step 3: Simulate TCP SYN Scan
A TCP SYN scan was generated using Nmap.

Command:
nmap -sS -p 1-100 127.0.0.1

yaml
Copy code

Snort generated alerts indicating detection of SYN-only packets.

📸 Screenshot Purpose:  
`ping_alert.png` shows the raw Snort alert confirming detection of the scan.

---

## Step 4: Alert Ingestion into ELK
Snort alerts were ingested into Elasticsearch via Logstash and verified in Kibana
using the `snort-logs-*` index.

📸 Screenshot Purpose:  
`tcp_discover.png` confirms alerts are searchable and properly parsed in Kibana Discover.

---

## Step 5: Kibana Investigation

### Source IP Analysis
A bar chart visualization was created to show alert frequency by source IP.

📸 Screenshot Purpose:  
`tcp_src_ip_bar.png` confirms the scan originated from a single source, consistent with reconnaissance.

---

### Destination Port Analysis
A table visualization was created to show which destination ports were targeted.

📸 Screenshot Purpose:  
`tcp_dst_port_table.png` demonstrates that multiple ports were probed, confirming scanning behavior.

---

### Timeline Analysis
A time-based visualization was created to analyze alert activity over time.

📸 Screenshot Purpose:  
`tcp_timeline.png` shows a short burst of activity, indicating a scan rather than persistent access.

---

## How Attackers Use TCP SYN Scans
Attackers use TCP SYN scans to:
- Identify open ports
- Discover listening services
- Determine potential attack vectors

If a service responds to a SYN packet, the attacker learns that the service is active
and may attempt exploitation (e.g., SSH brute force, web attacks, database access).

---

## Security Impact
While no data is accessed during a SYN scan, it exposes the system’s attack surface
and often precedes exploitation attempts.

---

## Mitigation Recommendations
- Close unused listening services
- Restrict access to exposed ports using firewalls
- Monitor for repeated scanning activity
- Apply rate limiting where appropriate

---

## Conclusion
This simulation demonstrates detection of reconnaissance activity using Snort and
investigation using Kibana to determine scope, pattern, and severity. The same
workflow applies to real-world SOC alert triage.
