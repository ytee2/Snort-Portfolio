# ELK Integration for Snort3 Alerts

This guide sets up a simple ELK Stack (Elasticsearch, Logstash, Kibana) to ingest Snort JSON alerts. Built on Kali Linux with Snort3.

## Prerequisites
- Kali Linux with Snort3 installed.
- Run in ~/Snort-Experiments for testing.
- 4GB+ RAM.

## Stages
sudo apt update
sudo apt install openjdk-21-jdk -y
java -version

OUTPUT:
 openjdk version "21.0.7" 2025-04-15
OpenJDK Runtime Environment (build 21.0.7+6-Debian-1)
OpenJDK 64-Bit Server VM (build 21.0.7+6-Debian-1, mixed mode, sharing)

Stage 2: Install Elasticsearch
Run in ~/Snort-Experiments:
bash# Add GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repo (8.x)
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update & install
sudo apt update
sudo apt install elasticsearch -y

# Config for single-node
sudo nano /etc/elasticsearch/elasticsearch.yml
add these lines in nano:
textnetwork.host: localhost
discovery.type: single-node


Save/exit.
bash# Start & enable
sudo systemctl daemon-reload
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# Test (with HTTPS/auth enabled)
curl -k https://localhost:9200/ -u elastic:'your password'

Output:
json{
  "name" : "kali",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "LnB7uNHRRpme-1ysdCpz6Q",
  "version" : {
    "number" : "8.19.4",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "aa0a7826e719b392e7782716b323c4fb8fa3b392",
    "build_date" : "2025-09-16T22:06:03.940754111Z",
    "build_snapshot" : false,
    "lucene_version" : "9.12.2",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}



Stage 3: Install Logstash
Run in ~/Snort-Experiments(or your created Elk folder):
bash# Repo already added from ES; update & install
sudo apt update
sudo apt install logstash -y

# Enable (don't start yet)
sudo systemctl enable logstash


### Stage 4: Install Kibana
Kibana provides the web UI for querying/visualizing Elasticsearch data (e.g., Snort alerts). It connects to ES, so if ES has security enabled (HTTPS/auth), Kibana setup involves tokens/passwords.

Commands:
```bash
sudo apt update
sudo apt install kibana -y
Config (edit with sudo nano /etc/kibana/kibana.yml):
textserver.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["https://localhost:9200"]  # Use HTTPS since ES is secured (changed from HTTP)
elasticsearch.username: "elastic"
elasticsearch.password:  # Your ES elastic user password (generated during ES install)
Start & enable:
bashsudo systemctl daemon-reload
sudo systemctl start kibana
sudo systemctl enable kibana
sudo ufw allow 5601/tcp

Test API 
curl -X GET "https://localhost:5601/api/status" -u elastic:"your password" -k  # Use HTTPS/auth


# Setup Process Explanation


Security/Auth: Since Elasticsearch was installed with security enabled (default in 8.x), Kibana requires an enrollment token or verification code to connect securely. The elastic password (D7+dnA*lh4x6eZ11_3bR) is the superuser cred from ES setup—use it for API tests and Kibana config.


Enrollment/Verification: On first browser access, Kibana prompts for a token. Generate with:
bashsudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana
(Output: A base64 token like eyJ2ZXIiOiI4LjE5LjQiLC...—paste into browser.)
If invalid, use verification code:
bashsudo /usr/share/kibana/bin/kibana-verification-code
(Output: Code like abcdef12-3456-7890-abcd-ef1234567890—paste in browser prompt.)


Browser Interface: After token/code, Kibana shows the welcome screen (dark/light theme selector). Log in with elastic/D7+dnA*lh4x6eZ11_3bR. It auto-configures with ES. If prompted for kibana_system password, run:
bashsudo /usr/share/kibana/bin/kibana-setup-passwords
(Generates/sets passwords—note them down.)
Interface Overview:

Left Sidebar: Stack Management (indexes), Discover (queries), Dashboard (visuals), Dev Tools (curl-like).
Home: Onboarding tour—skip or follow for basics.
First view: Empty Discover (no data yet)

Screenshot: /Snort-Portfolio/Images/Intergrations/kibana_interface.png

