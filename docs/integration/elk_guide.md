ELK Integration for Snort3 Alerts
This guide sets up a simple ELK Stack (Elasticsearch, Logstash, Kibana) to ingest Snort alert fast logs. Built on Kali Linux with Snort3.
Prerequisites

Kali Linux with Snort3 installed.
Run in ~/Snort-Experiments for testing.
4GB+ RAM.

Stages
Stage 1: Install Java
Already installed on system.
Output:
bashjava -version
textopenjdk version "21.0.7" 2025-04-15
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
Add:
textnetwork.host: localhost
discovery.type: single-node
Save/exit.
bash# Start & enable
sudo systemctl daemon-reload
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# Test (with HTTPS/auth enabled)
curl -k https://localhost:9200/ -u elastic:'D7+dnA*lh4x6eZ11_3bR'
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
Config Snippet (elasticsearch.yml):
textnetwork.host: localhost
discovery.type: single-node
ES Config
Stage 3: Install Logstash
Run in ~/Snort-Experiments:
bash# Repo already added from ES; update & install
sudo apt update
sudo apt install logstash -y

# Enable (don't start yet)
sudo systemctl enable logstash
Stage 4: Install Kibana
Kibana provides the web UI for querying/visualizing Elasticsearch data (e.g., Snort alerts). It connects to ES, so if ES has security enabled (HTTPS/auth), Kibana setup involves tokens/passwords.
Commands:
bashsudo apt update
sudo apt install kibana -y
Config (edit with sudo nano /etc/kibana/kibana.yml):
textserver.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["https://localhost:9200"]  # Use HTTPS since ES is secured
elasticsearch.username: "elastic"
elasticsearch.password: "yourpassword"  # Your ES elastic user password
Start & enable:
bashsudo systemctl daemon-reload
sudo systemctl start kibana
sudo systemctl enable kibana
sudo ufw allow 5601/tcp
Test API:
bashcurl -X GET "https://localhost:5601/api/status" -u elastic:"D7+dnA*lh4x6eZ11_3bR" -k  # Use HTTPS/auth
Setup Process Explanation

Security/Auth: Since Elasticsearch was installed with security enabled (default in 8.x), Kibana requires an enrollment token or verification code to connect securely. The elastic password (D7+dnA*lh4x6eZ11_3bR) is the superuser cred from ES setup—use it for API tests and Kibana config.
Enrollment/Verification: On first browser access, Kibana prompts for a token. Generate with:bashsudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana(Output: A base64 token like eyJ2ZXIiOiI4LjE5LjQiLC...—paste into browser.)If invalid, use verification code:bashsudo /usr/share/kibana/bin/kibana-verification-code(Output: Code like abcdef12-3456-7890-abcd-ef1234567890—paste in browser prompt.)
Browser Interface: After token/code, Kibana shows the welcome screen (dark/light theme selector). Log in with elastic/D7+dnA*lh4x6eZ11_3bR. It auto-configures with ES. If prompted for kibana_system password, run:bashsudo /usr/share/kibana/bin/kibana-setup-passwords(Generates/sets passwords—note them down.)Interface Overview:
Left Sidebar: Stack Management (indexes), Discover (queries), Dashboard (visuals), Dev Tools (curl-like).
Home: Onboarding tour—skip or follow for basics.
First view: Empty Discover (no data yet)—we'll add index pattern in Stage 7.


Kibana Welcome Interface
Stage 5: Configure Logstash for Snort Alert Fast Logs
Logstash reads Snort alert_fast.txt text alerts, parses fields with dissect/ruby, ships to ES.
Commands:
bashsudo nano /etc/logstash/conf.d/snort.conf  # Paste config below
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/snort.conf
sudo systemctl start logstash
Config (snort.conf):
textinput {
  file {
    path => "/var/log/snort/alert_fast.txt"
    start_position => "beginning"
    sincedb_path => "/var/log/logstash/snort_sincedb"
    codec => "plain"
  }
}
filter {
  # Drop non-alert lines
  if [message] !~ /^\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+/ {
    drop { }
  }
  # Use dissect instead of grok for more reliable parsing
  # Pattern 1: Try TCP/UDP with ports first
  dissect {
    mapping => {
      "message" => '%{month}/%{day}-%{hour}:%{minute}:%{second}.%{subsec} [**] [%{gid}:%{sid}:%{rev}] "%{alert_msg}" [**] [Priority: %{priority}] {%{proto}} %{src_ip}:%{src_port} -> %{dst_ip}:%{dst_port}'
    }
    tag_on_failure => ["_dissect_pattern1_failed"]
  }
  # Pattern 2: If pattern 1 failed, try ICMP/IP without ports
  if "_dissect_pattern1_failed" in [tags] {
    mutate {
      remove_tag => ["_dissect_pattern1_failed"]
    }
    dissect {
      mapping => {
        "message" => '%{month}/%{day}-%{hour}:%{minute}:%{second}.%{subsec} [**] [%{gid}:%{sid}:%{rev}] "%{alert_msg}" [**] [Priority: %{priority}] {%{proto}} %{src_ip} -> %{dst_ip}'
      }
      tag_on_failure => ["_dissect_pattern2_failed"]
    }
  }
  # Pattern 3: If pattern 2 failed, try incomplete alerts
  if "_dissect_pattern2_failed" in [tags] {
    mutate {
      remove_tag => ["_dissect_pattern2_failed"]
    }
    dissect {
      mapping => {
        "message" => '%{month}/%{day}-%{hour}:%{minute}:%{second}.%{subsec} [**] [%{gid}:%{sid}:%{rev}] "%{alert_msg}" [**] [Priority: %{priority}] {%{proto}} ->'
      }
      tag_on_failure => ["_dissectparsefailure_snort"]
    }
  }
  # Only proceed if dissect succeeded
  if "_dissectparsefailure_snort" not in [tags] {
    # Build timestamp from parsed fields
    ruby {
      code => '
        begin
          if event.get("month") && event.get("day") && event.get("hour") && event.get("minute") && event.get("second") && event.get("subsec")
            year = Time.now.year
            month = event.get("month").to_s.rjust(2, "0")
            day = event.get("day").to_s.rjust(2, "0")
            hour = event.get("hour").to_s.rjust(2, "0")
            minute = event.get("minute").to_s.rjust(2, "0")
            second = event.get("second").to_s.rjust(2, "0")
            subsec = event.get("subsec")
            ts = "#{year}/#{month}/#{day}-#{hour}:#{minute}:#{second}.#{subsec}"
            event.set("snort_timestamp", ts)
          end
        rescue => e
          event.tag("_rubyexception")
        end
      '
    }
    # Parse timestamp into @timestamp
    date {
      match => [ "snort_timestamp", "yyyy/MM/dd-HH:mm:ss.SSSSSS", "yyyy/MM/dd-HH:mm:ss.SSS" ]
      target => "@timestamp"
      timezone => "UTC"
      tag_on_failure => ["_dateparse                                                                                                                                                 


## Stage 6: Run Snort with Syslog Output
Snort logs alerts to syslog (via lua config).

Commands:
```bash
sudo grep -A2 "log_to_syslog" /etc/snort/snort.lua  # Verify syslog config
sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i eth0 -A fast -l /var/log/snort/ -v  # Run (syslog to /var/log/syslog)
sudo nmap -sS -p 80 example.com  # Traffic
sudo tail -f /var/log/syslog | grep snort  # Check syslog alerts
sudo journalctl -u logstash -f  # Ingest

Logstash Ingest (journalctl -u logstash -f): { "timestamp" : "10/04-04:50:06.272178", "pkt_num" : 3536, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 52, "dir" : "S2C", "src_ap" : "127.0.0.1:9200", "dst_ap" : "127.0.0.1:44558", "rule" : "116:150:1", "action" : "allow" }


Explanation: log_to_syslog sends to syslog. Tail checks alerts; Logstash parses and ingests to ES.

Screenshot: /Snort-Portfolio/Images/intergrations/index_pattern.png
Screenshot: /Snort-Portfolio/Images/intergrations/kibana_dashboard.png 
