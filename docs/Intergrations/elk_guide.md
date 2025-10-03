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
