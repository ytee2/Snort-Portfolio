# Snort 3 Intrusion Detection Portfolio

**SOC Analyst Home Lab** | Kali Linux · Snort 3 · ELK Stack · Nmap · Kibana

---

## Overview

This portfolio documents a fully functional SOC home lab built from scratch on Kali Linux. The goal was to simulate real-world attack scenarios, detect them using a custom-configured Snort 3 IDS, and investigate the resulting alerts through an ELK Stack pipeline — mirroring the workflow a SOC analyst follows in a professional environment.

The full detection lifecycle is covered:

**Attack Simulated → Snort Rule Fires → Alert Logged → Logstash Parses → Elasticsearch Indexes → Kibana Investigates → Incident Documented**

---

## Skills Demonstrated

- Snort 3 deployment and configuration on Kali Linux
- Custom detection rule authoring using `flags`, `content`, `http_uri`, `detection_filter`
- Attack simulation using industry-standard tools (Nmap, curl, dig)
- ELK Stack pipeline setup (Logstash → Elasticsearch → Kibana)
- Kibana dashboard creation for SOC-style alert triage
- Formal incident report writing with findings, severity, and recommendations
- Honest analysis of rule limitations and false positives

---

## Repository Structure
Snort-Portfolio/
├── Snort-Basics/
│   └── snort_installation.md
├── local.rules
├── Custom-Rules/
├── docs/
│   ├── simulations/
│   │   ├── icmp_test.md
│   │   ├── tcp_test.md
│   │   ├── udp_test.md
│   │   ├── http_test.md
│   │   └── DNS_test.md
│   ├── incident_reports/
│   │   ├── icmp_incident_report.md
│   │   ├── tcp_scam_report.md
│   │   ├── udp_incident_report.md
│   │   ├── http_incident_report.md
│   │   └── dns_incident_report.md
│   └── integration/
│       └── elk_guide.md
├── logs/
└── Images/
└── Intergrations/
├── kibana_interface.png
├── alert_types.png
├── alert_timeline.png
└── source_ips.png

---

## What I Built

### 1. Snort 3 IDS Setup
Installed and configured Snort 3 on Kali Linux, monitoring the loopback interface for local attack simulations and enp0s3 for live traffic. Wrote all detection rules manually in `local.rules`.

Full guide: [Snort-Basics/snort_installation.md](Snort-Basics/snort_installation.md)

---

### 2. Attack Simulations and Detections

**ICMP Ping Sweep**
- What it is: An attacker sends ping packets to discover live hosts on a network. The first step in any reconnaissance operation.
- How I simulated it: `ping -c 10 127.0.0.1`
- Rule: `alert icmp any any <> any any (msg:"ICMP any (bi)"; sid:9000003; rev:1;)`
- Result: Rule fired on both outgoing and incoming packets due to bidirectional `<>` matching. Over 50 alerts generated in under 2 seconds.
- Simulation: [docs/simulations/icmp_test.md](docs/simulations/icmp_test.md)
- Report: [docs/incident_reports/icmp_incident_report.md](docs/incident_reports/icmp_incident_report.md)

---

**TCP SYN Scan**
- What it is: An attacker sends SYN-only packets to multiple ports to identify which services are running, without completing the TCP handshake.
- How I simulated it: `nmap -sS -p 1-100 127.0.0.1`
- Rule: `alert tcp any any -> any any (msg:"TCP SYN scan detected"; flags:S; sid:9000004; rev:1;)`
- Result: Rule fired on SYN packets sent to 7+ different ports within 22 seconds, confirming scanning behaviour.
- Simulation: [docs/simulations/tcp_test.md](docs/simulations/tcp_test.md)
- Report: [docs/incident_reports/tcp_scam_report.md](docs/incident_reports/tcp_scam_report.md)

---

**UDP Scan**
- What it is: An attacker probes UDP ports to discover services that don't use TCP, such as DNS, SNMP, and NTP.
- How I simulated it: `nmap -sU -p 1-100 127.0.0.1`
- Rule: `alert udp any any -> any any (msg:"UDP Scan Detected"; sid:9000005; rev:1;)`
- Result: Rule fired but also caught legitimate DNS and QUIC traffic — identified as a false positive issue caused by an overly broad rule. Documented as a learning point.
- Simulation: [docs/simulations/udp_test.md](docs/simulations/udp_test.md)
- Report: [docs/incident_reports/udp_incident_report.md](docs/incident_reports/udp_incident_report.md)

---

**HTTP Directory Traversal**
- What it is: An attacker manipulates URL paths using `../` sequences to access files outside the web server's intended directory.
- How I simulated it: `curl "http://localhost/../etc/passwd"` with a Python HTTP server running
- Rule: `alert tcp any any -> any 80 (msg:"HTTP Directory Traversal Detected"; content:"../"; http_uri; sid:9000006; rev:1;)`
- Result: Rule did not fire. Identified that `http_uri` requires Snort's HTTP inspector to be active. Documented the troubleshooting process.
- Simulation: [docs/simulations/http_test.md](docs/simulations/http_test.md)
- Report: [docs/incident_reports/http_incident_report.md](docs/incident_reports/http_incident_report.md)

---

**DNS Flood**
- What it is: An attacker sends a high volume of DNS queries to overwhelm a DNS server or conduct rapid subdomain enumeration.
- How I simulated it: `for i in {1..60}; do dig @127.0.0.1 evil.com & done; wait`
- Rule: `alert udp any any -> any 53 (msg:"DNS Flood Detected"; detection_filter: track by_src, count 50, seconds 10; sid:9000008; rev:1;)`
- Result: Rule did not fire during initial test. Identified that sequential `dig` queries are too slow to hit the 50-per-10-second threshold. Documented fix using parallel queries with `&`.
- Simulation: [docs/simulations/DNS_test.md](docs/simulations/DNS_test.md)
- Report: [docs/incident_reports/dns_incident_report.md](docs/incident_reports/dns_incident_report.md)

---

**SSH Brute-Force**
- What it is: An attacker uses automated tools to rapidly try thousands of username and password combinations against an SSH server. One of the most common attacks seen in real SOC environments.
- How I simulated it: `hydra -l root -P passwords.txt ssh://127.0.0.1 -t 4 -V`
- Rule: `alert tcp any any -> any 22 (msg:"SSH Brute Force Detected"; detection_filter: track by_src, count 5, seconds 60; sid:9000009; rev:1;)`
- Result: Rule did not fire on loopback due to SSH encryption and stream handling limitations. tcpdump confirmed attack traffic was present. Rule verified as correctly loaded by Snort. Documented why it would fire correctly on a live network interface.
- Simulation: [docs/simulations/ssh_test.md](docs/simulations/ssh_test.md)
- Report: [docs/incident_reports/ssh_incident_report.md](docs/incident_reports/ssh_incident_report.md)
---

### 3. ELK Stack Integration

Configured a full Logstash pipeline to parse Snort's `alert_fast.txt` log format and ship alerts to Elasticsearch. Built three Kibana dashboards for SOC-style investigation.

**Pipeline:** Snort alert_fast.txt → Logstash (dissect parser) → Elasticsearch (`snort-logs-*`) → Kibana

**Total alerts indexed: 218,104**

**Kibana Dashboards:**

- Alert Types Bar Chart — shows which rules fired most frequently
- Source IP Table — identifies scanning origin IPs
- Alert Timeline — shows burst activity vs persistent scanning over time

Full guide: [docs/integration/elk_guide.md](docs/integration/elk_guide.md)

Screenshots:
- [kibana_interface.png](Images/Intergrations/kibana_interface.png) — Kibana first login
- [index_pattern.png](Images/Intergrations/index_pattern.png) — snort-logs-* index pattern setup
- [alert_types.png](Images/Intergrations/alert_types.png) — Alert types bar chart
- [alert_timeline.png](Images/Intergrations/alert_timeline.png) — Alert timeline dashboard
- [source_ips.png](Images/Intergrations/source_ips.png) — Source IP table
- [kibana_dashboard.png](Images/Intergrations/kibana_dashboard.png) — Full Snort IDS dashboard
---

## Lab Setup

| Item | Detail |
|------|--------|
| OS | Kali Linux |
| Snort Version | 3.1.82.0 |
| Interface | lo (testing) / enp0s3 (live) |
| Elasticsearch | 8.19.4 |
| Logstash | 8.19.4 |
| Kibana | 8.19.4 |

**Standard Snort run command:**
```bash
sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A fast -l /var/log/snort -v
```

---

## Key Lessons Learned

- A bidirectional Snort rule (`<>`) fires on both request and reply packets — useful for catching full conversations but generates double the alerts
- Broad rules like `alert udp any any -> any any` catch everything including legitimate traffic — production rules need scope and thresholds
- Application-layer keywords like `http_uri` require the corresponding Snort inspector to be active — rule syntax alone is not enough
- `detection_filter` thresholds require traffic to be generated in parallel, not sequentially, to actually trigger
- Elasticsearch 8.x in a single-node lab uses HTTP not HTTPS — always verify protocol before troubleshooting connection issues

---

## Future Work

- [ ] Add Wireshark PCAP analysis for each attack simulation
- [ ] Test Snort 3 inline mode (IPS — actually block traffic, not just detect)
- [ ] Simulate multi-stage attack (recon → exploit → exfil)
- [ ] Tune UDP and HTTP rules to reduce false positives
- [x] Add SSH brute-force detection rule
---

*Built: September 2025 — ongoing | Snort 3.1.82.0 · ELK 8.19.4 · Kali Linux*
