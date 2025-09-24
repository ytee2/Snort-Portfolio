# ICMP Test Simulation

## Objective
Test Snort’s ability to detect ICMP (ping) traffic.

## Steps
#1. Verified Snort version:
   ```bash
   snort -V

Screenshot:![Snort Startup Output] /Snort-Portfolio/images/simulations/icmp/snort_version.png

#2. Identify your network interface (commonly eth0 in Kali):

   ip route get 8.8.8.8 | awk '{print $5; exit}'


##3.   Rules Setup

### 3.1 Check Snort’s RULE_PATH
Run the following command to locate Snort’s rule directory:
```bash
grep RULE_PATH /etc/snort/snort_defaults.lua 2>/dev/null \
|| grep RULE_PATH /usr/local/etc/snort/snort_defaults.lua

Create the Rules Folder (if missing):
  sudo mkdir -p /etc/rules(The rule path is assumed to be /etc/rules for everyone in this case)

### 3.2 : Create the rule file 
sudo nano /etc/rules/local.rules
 Add this rule :
alert icmp any any -> any any (msg:"ICMP echo request"; itype:8; sid:1000001; rev:1;)


### 3.3
alert icmp any any -> any any (msg:"ICMP echo request"; itype:8; sid:1000001; rev:1;)

### 3.4
Configure Snort to use the rule:
Open /etc/snort/snort.lua and find the ips block. Add: 

ips =
{
  variables = default_variables,

  rules = [[
    include $RULE_PATH/local.rules
  ]]
}

Make sure the rules line is inside the ips = {} block and after the variables.

### 3.5 
Validate configuration:
sudo snort -T -c /etc/snort/snort.lua



4. 
## 4.1  Run Snort and generate ping traffic
Prepare the Logging Directory
sudo mkdir -p /var/log/snort


sudo mkdir -p /var/log/snort
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast -R ~/Snort-Portfolio/local.rules
NB : (replace eth0 with your interface if different)
ping 8.8.8.8
Screenshot:![Snort Startup Output] Images/simulations/icmp/ping.png


