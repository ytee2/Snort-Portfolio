# 🛡️ Snort Intrusion Detection Lab  

## 📖 Overview  
This repository documents my setup, configuration, and testing of **Snort**, an open-source intrusion detection and prevention system (IDS/IPS).  
The goal of this project is to demonstrate practical skills in network security monitoring, rule creation, and traffic analysis.  



## ⚙️ Setup & Installation  
Operating System: Kali Linux  
 Installed Snort using:  

bash
sudo apt update && sudo apt install snort -y

Configured Snort to monitor interface: enp0s3

👉 Detailed step-by-step installation guide is available in:
snort_installation.md




Lab Demonstration

Created and tested custom Snort rules

Captured and analyzed network traffic (ICMP, HTTP, port scans, etc.)

Detected suspicious activities such as:

Ping sweeps

Port scanning (Nmap)

Abnormal DNS queries




Learning Outcomes:

Practical understanding of IDS concepts

Experience with Snort rule writing and traffic analysis

Hands-on incident detection skills




Future Work

Integrate Snort with ELK Stack for log monitoring

Experiment with Snort3 features

Expand lab to simulate real-world attack scenarios





Acknowledgments

Snort official docs

Kali Linux Documentation

Various open-source cybersecurity resources
