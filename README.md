Snort 3 Intrusion Detection Portfolio

SOC Analyst Lab | Kali Linux · Snort 3 · ELK Stack · Nmap · Wireshark

A hands-on portfolio documenting the full detection lifecycle — from custom rule creation through alert triage, log ingestion, and Kibana investigation — using Snort 3 as an IDS on Kali Linux.

What This Portfolio Demonstrates
SkillEvidenceSnort 3 deployment & configurationSnort-Basics/snort_installation.mdCustom detection rule authoringlocal.rules, Custom-Rules/Attack simulation & traffic generationdocs/simulations/Alert analysis & incident documentationdocs/incident_reports/ELK Stack integration (log ingestion + Kibana)docs/integration/elk_guide.md

Repository Structure
Snort-Portfolio/
├── Snort-Basics/
│   └── snort_installation.md       # Step-by-step Snort 3 setup on Kali Linux
├── local.rules                     # All custom Snort detection rules
├── Custom-Rules/                   # Extended rule sets with documentation
├── docs/
│   ├── simulations/                # Attack simulations with commands & screenshots
│   │   ├── icmp_test.md
│   │   ├── tcp_test.md
│   │   ├── udp_test.md
│   │   ├── http_test.md
│   │   └── DNS_test.md
│   ├── incident_reports/           # Formal incident reports per detection
│   │   ├── tcp_scam_report.md
│   │   ├── icmp_incident_report.md
│   │   ├── udp_incident_report.md
│   │   ├── http_incident_report.md
│   │   └── dns_incident_report.md
│   └── integration/
│       └── elk_guide.md            # Logstash pipeline + Kibana setup
├── logs/                           # Sample Snort alert logs
└── Images/                         # Screenshots from simulations & Kibana

Detections Covered
1. ICMP Ping Sweep

Technique: Host discovery via ICMP Echo Requests (nmap -sn)
Rule: alert icmp any any -> any any (msg:"ICMP Ping Sweep"; sid:9000001;)
Simulation: docs/simulations/icmp_test.md
Report: docs/incident_reports/icmp_incident_report.md

2. TCP SYN Scan

Technique: Port discovery via half-open SYN packets (nmap -sS)
Rule: alert tcp any any -> any any (msg:"TCP SYN scan detected"; flags:S; sid:9000004;)
Simulation: docs/simulations/tcp_test.md
Report: docs/incident_reports/tcp_scam_report.md

3. UDP Scan / Flood

Technique: UDP service enumeration and flooding (nmap -sU)
Rule: alert udp any any -> any any (msg:"UDP Scan detected"; sid:9000003;)
Simulation: docs/simulations/udp_test.md
Report: docs/incident_reports/udp_incident_report.md

4. HTTP Directory Traversal

Technique: Path traversal via ../ sequences in HTTP requests (curl)
Rule: alert http any any -> any any (msg:"HTTP Directory Traversal"; content:"../"; sid:9000006;)
Simulation: docs/simulations/http_test.md
Report: docs/incident_reports/http_incident_report.md

5. DNS Flood

Technique: High-rate DNS query flooding (dig loop / dnsrecon)
Rule: threshold-based detection on UDP/53 packet rate
Simulation: docs/simulations/DNS_test.md
Report: docs/incident_reports/dns_incident_report.md


Lab Setup
Operating System: Kali Linux
Snort Version: 3.1.82.0
Monitoring Interface: lo (loopback for local testing; enp0s3 for live traffic)
Standard Snort run command:
bashsudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A fast -l /var/log/snort -v
Tools used for simulation:

nmap — TCP/UDP/ICMP scanning
curl — HTTP request crafting
dig — DNS query generation
tcpdump — Packet capture validation

👉 Full installation walkthrough: Snort-Basics/snort_installation.md

ELK Stack Integration
Snort alerts are shipped to Elasticsearch via a Logstash pipeline and visualised in Kibana.
Investigation workflow per alert:

Discover tab → confirm alert ingestion (snort-logs-* index)
Source IP bar chart → identify scanning origin
Destination port table → confirm scan breadth
Timeline visualisation → determine burst pattern vs. persistent access

👉 Full setup guide: docs/integration/elk_guide.md

Skills Demonstrated

IDS deployment and configuration (Snort 3)
Snort rule syntax: flags, content, detection_filter, threshold
Attack simulation using industry-standard tools
SOC-style incident documentation (summary, findings, severity, recommendations)
Log ingestion pipeline (Logstash → Elasticsearch)
Kibana dashboard creation for alert triage


Future Work

 Add PCAP files alongside simulations as supporting evidence
 Add Kibana dashboard screenshots to Images/
 Experiment with Snort 3 inline (IPS) mode
 Simulate multi-stage attack scenario (recon → exploit → exfil)
 Add detection for brute-force SSH attempts


Built: September 2025 — ongoing | Tools: Snort 3.1.82.0, Nmap, ELK Stack, Kali Linux
