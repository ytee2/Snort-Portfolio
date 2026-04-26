# Incident Report: SSH Brute-Force Detection

## Summary
A simulated SSH brute-force attack was conducted using Hydra v9.5 against the
local SSH server (127.0.0.1:22). 20 login attempts were made using common
passwords targeting the root account. Snort rule sid:9000009 was configured to
detect this activity but did not fire during loopback testing due to limitations
of SSH traffic handling on the lo interface.

---

## Detection Details
- **Tool:** Snort 3.1.82.0
- **Rule:** `alert tcp any any -> any 22 (msg:"SSH Brute Force Detected"; detection_filter: track by_src, count 5, seconds 60; sid:9000009; rev:1;)`
- **SID:** 9000009
- **Attack Tool:** Hydra v9.5
- **Interface Monitored:** lo (loopback)
- **Result:** No alerts generated on loopback

---

## What Was Observed
- 20 rapid login attempts from 127.0.0.1 to 127.0.0.1:22
- 4 parallel threads used by Hydra — consistent with automated tooling
- Attack completed in 21 seconds (15:27:24 to 15:27:46)
- All attempts failed — no valid credentials found
- tcpdump confirmed SSH traffic was present on lo during the attack
- Snort rule verified as loaded correctly via `--dump-rule-meta`

---

## Why This Matters in a Real Environment
SSH brute-force is one of the most common attacks seen in SOC environments.
Any server with port 22 exposed to the internet receives automated brute-force
attempts constantly from botnets using tools like Hydra and Medusa.

A single legitimate SSH login involves one connection to port 22. A brute-force
involves hundreds of connections in a short window from the same source IP —
a pattern that is easy to detect with a threshold-based rule.

---

## Why the Rule Did Not Fire
Three factors caused the rule to not fire during loopback testing:

1. **SSH encryption** — SSH negotiates an encrypted session immediately, making
   each Hydra attempt a full encrypted stream rather than a simple packet.
   Snort's `detection_filter` counts streams differently for encrypted sessions.

2. **Loopback limitations** — The lo interface triggers Snort decoder alerts
   (116:150, 116:151) on all traffic, indicating packets are processed at
   decoder level before reaching custom detection rules.

3. **Stream tracking** — `detection_filter` accumulates counts within a session
   but resets between sessions. Hydra opens a new session per attempt, so the
   counter never reaches the threshold of 5.

---

## Severity
**High** — SSH brute-force is a precursor to full system compromise. A successful
login gives an attacker complete remote control of the system. Even failed attempts
consume server resources and indicate active targeting.

---

## Recommendations
- Deploy the rule on enp0s3 to monitor real inbound SSH traffic
- Implement `fail2ban` alongside Snort for active blocking of brute-force IPs
- Disable SSH password authentication — use key-based authentication only
- Change SSH from default port 22 to reduce automated scanning noise
- Rate-limit SSH connections at the firewall level

---

## Simulation Command Used
```bash
hydra -l root -P ~/small_passwords.txt ssh://127.0.0.1 -t 4 -V
```

## Snort Run Command
```bash
sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A fast -l /var/log/snort -v
```
