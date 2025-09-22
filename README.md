# Snort Intrusion Detection Portfolio

This repository documents my setup, configuration, and testing of Snort 3, an open-source intrusion detection and prevention system (IDS/IPS). The goal is to demonstrate practical skills in network security monitoring, rule creation, and traffic analysis on Kali Linux.

## Sections
- [ICMP Ping Sweep Detection](docs/icmp.md): Basic network discovery alerts.
- [TCP SYN Scan Detection](docs/tcp.md): Port scan detection.
- [UDP Scan/Flood Detection](docs/udp_test.md): Connectionless probes.
- [HTTP Directory Traversal Detection](docs/http.md): App-layer attacks.
- [DNS Flood Detection](docs/dns.md): Suspicious query rate limiting.

## Setup & Installation
Operating System: Kali Linux  
Installed Snort using:  
```bash
sudo apt update && sudo apt install snort -y
Configured Snort to monitor interface: lo (for local testing; switch to enp0s3 for live traffic).
👉 Detailed step-by-step installation guide: snort_installation.md
Lab Demonstrations
Created and tested custom Snort rules in local.rules.
Captured and analyzed network traffic using nmap, curl, dig, and tcpdump.
Detected suspicious activities such as:

Ping sweeps (ICMP)
Port scanning (Nmap TCP/UDP)
Abnormal DNS queries/floods
HTTP directory traversal

Example run command:
bashsudo snort -c /etc/snort/snort.lua -R local.rules -i lo -A alert_full -k none -l /var/log/snort
Learning Outcomes

Practical understanding of IDS concepts (passive mode, thresholds).
Experience with Snort rule writing (flags, content, detection_filter).
Hands-on incident detection and troubleshooting (e.g., local traffic capture).

Future Work

Integrate Snort with ELK Stack for log monitoring.
Experiment with Snort 3 inline mode.
Expand lab to simulate real-world attack scenarios (e.g., multi-stage).

Acknowledgments

Snort official docs: https://www.snort.org/documents
Kali Linux Documentation
Various open-source cybersecurity resources

Built: September 22, 2025 | Tools: Snort 3.1.82.0, nma, curl, dig.
