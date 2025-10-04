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


### Stage 5: Configure Logstash for Snort Alerts
Logstash parses Snort JSON alerts (timestamp, SID, msg, IPs) and ships to ES.

Commands:
```bash
sudo nano /etc/logstash/conf.d/snort.conf  # Paste config below
Config (snort.conf):
textinput {
  file {
    path => "/var/log/snort/alert_json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  grok {
    match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} $$ %{INT:sid}\:%{INT:rev} $$ %{GREEDYDATA:msg} $$ %{WORD:proto} $$ %{IP:src_ip}:%{INT:src_port} -> %{IP:dst_ip}:%{INT:dst_port}" }
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "D7+dnA*lh4x6eZ11_3bR"
    index => "snort-alerts-%{+YYYY.MM.dd}"
    ssl_verification_mode => "certificate"
  }
  stdout { codec => rubydebug }
}
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/snort.conf
sudo systemctl start logstash

Test Output:Using bundled JDK: /usr/share/logstash/jdk
WARNING: Could not find logstash.yml which is typically located in $LS_HOME/config or /etc/logstash. You can specify the path using --path.settings. Continuing using the defaults
Could not find log4j2 configuration at path /usr/share/logstash/config/log4j2.properties. Using default config which logs errors to the console
[WARN ] 2025-10-04 03:55:18.388 [main] runner - Starting from version 9.0, running with superuser privileges is not permitted unless you explicitly set 'allow_superuser' to true, thereby acknowledging the possible security risks
[WARN ] 2025-10-04 03:55:18.397 [main] runner - NOTICE: Running Logstash as a superuser is strongly discouraged as it poses a security risk. Set 'allow_superuser' to false for better security.
[WARN ] 2025-10-04 03:55:18.407 [main] runner - 'pipeline.buffer.type' setting is not explicitly defined.Before moving to 9.x set it to 'heap' and tune heap size upward, or set it to 'direct' to maintain existing behavior.
[INFO ] 2025-10-04 03:55:18.408 [main] runner - Starting Logstash {"logstash.version"=>"8.19.4", "jruby.version"=>"jruby 9.4.9.0 (3.1.4) 2024-11-04 547c6b150e OpenJDK 64-Bit Server VM 21.0.8+9-LTS on 21.0.8+9-LTS +indy +jit [x86_64-linux]"}
[INFO ] 2025-10-04 03:55:18.433 [main] runner - JVM bootstrap flags: [-Xms1g, -Xmx1g, -Djava.awt.headless=true, -Dfile.encoding=UTF-8, -Djruby.compile.invokedynamic=true, -XX:+HeapDumpOnOutOfMemoryError, -Djava.security.egd=file:/dev/urandom, -Dlog4j2.isThreadContextMapInheritable=true, -Djruby.regexp.interruptible=true, -Djdk.io.File.enableADS=true, --add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED, --add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED, --add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED, --add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED, --add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED, --add-opens=java.base/java.security=ALL-UNNAMED, --add-opens=java.base/java.io=ALL-UNNAMED, --add-opens=java.base/java.nio.channels=ALL-UNNAMED, --add-opens=java.base/sun.nio.ch=ALL-UNNAMED, --add-opens=java.management/sun.management=ALL-UNNAMED, -Dio.netty.allocator.maxOrder=11]
[INFO ] 2025-10-04 03:55:19.076 [main] StreamReadConstraintsUtil - Jackson default value override `logstash.jackson.stream-read-constraints.max-string-length` configured to `200000000` (logstash default)
[INFO ] 2025-10-04 03:55:19.120 [main] StreamReadConstraintsUtil - Jackson default value override `logstash.jackson.stream-read-constraints.max-number-length` configured to `10000` (logstash default)
[INFO ] 2025-10-04 03:55:19.120 [main] StreamReadConstraintsUtil - Jackson default value override `logstash.jackson.stream-read-constraints.max-nesting-depth` configured to `1000` (logstash default)
[WARN ] 2025-10-04 03:55:20.379 [LogStash::Runner] multilocal - Ignoring the 'pipelines.yml' file because modules or command line options are specified
[INFO ] 2025-10-04 03:55:21.214 [LogStash::Runner] Reflections - Reflections took 196 ms to scan 1 urls, producing 150 keys and 530 values
[INFO ] 2025-10-04 03:55:22.146 [LogStash::Runner] javapipeline - Pipeline `main` is configured with `pipeline.ecs_compatibility: v8` setting. All plugins in this pipeline will default to `ecs_compatibility => v8` unless explicitly configured otherwise.
Configuration OK
[INFO ] 2025-10-04 03:55:22.157 [LogStash::Runner] runner - Using config.test_and_exit mode. Config Validation Result: OK. Exiting Logstash
                                                                                                                                                 


### Stage 6: Run Snort with JSON Output
Snort 3 JSON via lua config (file: alert_json.txt).

Commands:
```bash
sudo grep -A2 "alert_json" /etc/snort/snort.lua  # Verify
sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i eth0 -A fast -l /var/log/snort/ -v  # Run
sudo nmap -sS -p 80 example.com  # Traffic
ls -la /var/log/snort/  # Check
sudo cat /var/log/snort/alert_json.txt  # JSON
sudo journalctl -u logstash -f  # Ingest

Sample JSON (sudo cat /var/log/snort/alert_json.txt): { "timestamp" : "10/04-04:58:42.408710", "pkt_num" : 4886, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 52, "dir" : "C2S", "src_ap" : "127.0.0.1:60096", "dst_ap" : "127.0.0.1:9200", "rule" : "116:150:1", "action" : "allow" }

Logstash Ingest (journalctl -u logstash -f): { "timestamp" : "10/04-04:50:06.272178", "pkt_num" : 3536, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 52, "dir" : "S2C", "src_ap" : "127.0.0.1:9200", "dst_ap" : "127.0.0.1:44558", "rule" : "116:150:1", "action" : "allow" }


