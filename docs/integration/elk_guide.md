# ELK Integration for Snort 3 Alerts

This guide documents the working ELK Stack setup used to ingest, parse, and
visualise Snort 3 alerts on Kali Linux. Alerts flow from Snort → Logstash →
Elasticsearch → Kibana.

---

## Stack Versions
- Elasticsearch 8.19.4
- Logstash 8.19.4
- Kibana 8.19.4
- Java: OpenJDK 21.0.7
- Snort: 3.1.82.0

---

## Prerequisites
- Kali Linux with Snort 3 installed and working
- 4GB+ RAM
- Snort alerts writing to `/var/log/snort/alert_fast.txt`

---

## Stage 1: Install Java
```bash
sudo apt update
sudo apt install openjdk-21-jdk -y
java -version
```
Output confirms: `openjdk version "21.0.7"`

---

## Stage 2: Install Elasticsearch
```bash
# Add GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repo
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install
sudo apt update
sudo apt install elasticsearch -y
```

Configure for single-node (`sudo nano /etc/elasticsearch/elasticsearch.yml`):
network.host: localhost
discovery.type: single-node

Start and enable:
```bash
sudo systemctl daemon-reload
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
```

Verify (note: HTTP not HTTPS — security disabled for lab):
```bash
curl -u elastic:'YOUR_PASSWORD' "http://localhost:9200/"
```

---

## Stage 3: Install Logstash
```bash
sudo apt update
sudo apt install logstash -y
sudo systemctl enable logstash
```

---

## Stage 4: Install Kibana
```bash
sudo apt update
sudo apt install kibana -y
```

Configure (`sudo nano /etc/kibana/kibana.yml`):
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "YOUR_PASSWORD"

Start and enable:
```bash
sudo systemctl daemon-reload
sudo systemctl start kibana
sudo systemctl enable kibana
sudo ufw allow 5601/tcp
```

Access Kibana at `http://localhost:5601`.
On first access, generate an enrollment token:
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana
```
Or use verification code:
```bash
sudo /usr/share/kibana/bin/kibana-verification-code
```

Screenshot: `Images/Intergrations/kibana_interface.png`

---

## Stage 5: Configure Logstash Pipeline

This is the working pipeline config. It reads Snort's alert_fast log,
handles both TCP/UDP alerts (with ports) and ICMP alerts (without ports),
parses timestamps, categorises alerts by GID, and enriches external IPs
with GeoIP data.

```bash
sudo nano /etc/logstash/conf.d/snort.conf
```

Paste this config:

```ruby
input {
  file {
    path => "/var/log/snort/alert_fast.txt"
    start_position => "beginning"
    sincedb_path => "/var/log/logstash/snort_sincedb"
    codec => "plain"
  }
}

filter {
  if [message] !~ /^\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+/ {
    drop { }
  }
  dissect {
    mapping => {
      "message" => '%{month}/%{day}-%{hour}:%{minute}:%{second}.%{subsec} [**] [%{gid}:%{sid}:%{rev}] "%{alert_msg}" [**] [Priority: %{priority}] {%{proto}} %{src_ip}:%{src_port} -> %{dst_ip}:%{dst_port}'
    }
    tag_on_failure => ["_dissect_pattern1_failed"]
  }
  if "_dissect_pattern1_failed" in [tags] {
    mutate { remove_tag => ["_dissect_pattern1_failed"] }
    dissect {
      mapping => {
        "message" => '%{month}/%{day}-%{hour}:%{minute}:%{second}.%{subsec} [**] [%{gid}:%{sid}:%{rev}] "%{alert_msg}" [**] [Priority: %{priority}] {%{proto}} %{src_ip} -> %{dst_ip}'
      }
      tag_on_failure => ["_dissectparsefailure_snort"]
    }
  }
  if "_dissectparsefailure_snort" not in [tags] {
    ruby {
      code => '
        begin
          year = Time.now.year
          month = event.get("month").to_s.rjust(2,"0")
          day = event.get("day").to_s.rjust(2,"0")
          hour = event.get("hour").to_s.rjust(2,"0")
          minute = event.get("minute").to_s.rjust(2,"0")
          second = event.get("second").to_s.rjust(2,"0")
          subsec = event.get("subsec")
          event.set("snort_timestamp","#{year}/#{month}/#{day}-#{hour}:#{minute}:#{second}.#{subsec}")
        rescue => e
          event.tag("_rubyexception")
        end
      '
    }
    date {
      match => ["snort_timestamp", "yyyy/MM/dd-HH:mm:ss.SSSSSS"]
      target => "@timestamp"
      timezone => "UTC"
      tag_on_failure => ["_dateparsefailure"]
    }
    mutate {
      remove_field => ["snort_timestamp","month","day","hour","minute","second","subsec"]
      convert => { "priority" => "integer" "sid" => "integer" "gid" => "integer" "rev" => "integer" }
    }
    if [gid] == "1" { mutate { add_field => { "alert_category" => "custom_rule" } } }
    else if [gid] == "116" { mutate { add_field => { "alert_category" => "decoder_alert" } } }
    else if [gid] == "122" { mutate { add_field => { "alert_category" => "portscan_alert" } } }
    else { mutate { add_field => { "alert_category" => "other" } } }
    if [src_ip] and [src_ip] !~ /^(10\.|192\.168\.)/ {
      geoip { source => "src_ip" target => "src_geoip" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "snort-logs-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "YOUR_PASSWORD"
  }
}
```

Validate and start:
```bash
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/snort.conf
sudo systemctl start logstash
```

Verify data is flowing:
```bash
curl -u elastic:'YOUR_PASSWORD' "http://localhost:9200/snort-logs-*/_count"
```
Expected output: `{"count":218104,...}` — confirms alerts are indexed.

---

## Stage 6: Kibana Dashboards

Index pattern: `snort-logs-*` (timestamp field: `@timestamp`)

Three dashboards built under **Snort IDS Dashboard**:

### Alert Types Bar Chart
Shows which Snort rules fired most frequently.
- Field: `alert_msg.keyword`
- Chart type: Vertical Bar
- Screenshot: `Images/Intergrations/alert_types.png`

### Source IP Table
Shows which IPs generated the most alerts.
- Field: `src_ip.keyword`
- Chart type: Table
- Screenshot: `Images/Intergrations/source_ips.png`

### Alert Timeline
Shows alert volume over time to identify burst activity vs persistent scanning.
- Field: `@timestamp`
- Chart type: Bar over time
- Screenshot: `Images/Intergrations/alert_timeline.png`

---

## Key Lessons Learned

- Elasticsearch 8.x defaults to HTTP in single-node lab mode — use
  `http://` not `https://` in Logstash output and curl commands
- The `dissect` plugin is more reliable than `grok` for fixed-format
  Snort alerts — pattern 1 handles TCP/UDP (with ports), pattern 2
  handles ICMP (without ports)
- Index name must match between Logstash output and Kibana index pattern
  — this pipeline uses `snort-logs-*`
- `detection_filter` in Snort rules requires traffic volume threshold
  to be met before any alert fires — always test with parallel requests
