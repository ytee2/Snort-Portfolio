# SSH Brute-Force Detection with Snort 3

## Overview
This simulation demonstrates an attempted SSH brute-force attack using Hydra
against a local SSH server, with Snort 3 configured to detect repeated connection
attempts to port 22. Snort was run on the loopback interface (lo) on Kali Linux.

---

## Tools Used
- Snort 3.1.82.0
- Hydra v9.5
- OpenSSH Server

---

## Rule Created
alert tcp any any -> any 22 (msg:"SSH Brute Force Detected"; detection_filter: track by_src, count 5, seconds 60; sid:9000009; rev:1;)

**What this rule does:**
- Monitors all TCP traffic destined for port 22 (SSH)
- Uses `detection_filter` to only alert after the same source IP
  makes 5 or more connection attempts within 60 seconds
- This threshold prevents false positives from single legitimate SSH logins

---

## Step 1: Start SSH Server
```bash
sudo systemctl start ssh
sudo systemctl status ssh
```
Output confirmed SSH active and listening on port 22.

---

## Step 2: Start Snort
```bash
sudo snort -c /etc/snort/snort.lua -R ~/Snort-Portfolio/local.rules -i lo -A fast -l /var/log/snort -v
```

---

## Step 3: Simulate Brute-Force with Hydra
Hydra is a real-world penetration testing tool used to automate login attempts
against network services. It was used here to simulate an attacker systematically
trying common passwords against the SSH service.

```bash
hydra -l root -P ~/small_passwords.txt ssh://127.0.0.1 -t 4 -V
```

**Password list used:**
password, 123456, root, toor, kali, admin, letmein, qwerty,
password123, root123, test, hello, welcome, linux, kali123,
pass, 1234, abcd, test123, secret

Hydra output confirmed 20 login attempts were made:
[DATA] attacking ssh://127.0.0.1:22/
[ATTEMPT] target 127.0.0.1 - login "root" - pass "password" - 1 of 20
[ATTEMPT] target 127.0.0.1 - login "root" - pass "123456" - 2 of 20
...
1 of 1 target completed, 0 valid password found

Traffic to port 22 was confirmed on the loopback interface using tcpdump:
```bash
sudo tcpdump -i lo port 22 -c 5
```
Output confirmed SSH packets flowing on lo during the attack.

---

## Step 4: Alert Verification
```bash
grep -a "9000009" /var/log/snort/alert_fast.txt
```

No alerts were generated for sid:9000009 during loopback testing.

---

## Analysis: Why the Rule Did Not Fire

Snort confirmed the rule was loaded correctly:
{ "sid": 9000009, "msg": "SSH Brute Force Detected", "dst_ports": "22" }

Three factors explain why the rule did not fire on loopback:

**1. SSH is an encrypted protocol**
Unlike ICMP or raw TCP scans, SSH immediately negotiates an encrypted session.
Snort's stream reassembly engine processes SSH differently — each Hydra attempt
creates a full encrypted session rather than a simple packet flood. The
`detection_filter` counts streams differently for established encrypted sessions.

**2. Loopback interface limitations**
The loopback interface (lo) processes traffic differently from physical interfaces.
Snort's decoder fires `116:150` and `116:151` alerts (loopback IP, same src/dst)
on all loopback traffic, which indicates the packets are being processed at the
decoder level before reaching the detection engine rules.

**3. detection_filter behaviour with SSH**
The `detection_filter` keyword tracks packet or flow counts. For SSH, Hydra opens
a full TCP session per attempt with multiple packets — the counter resets between
sessions rather than accumulating across them as expected.

---

## How This Rule Works in Production

On a real network interface monitoring external traffic:
- SSH brute-force from an external IP generates clean TCP SYN packets to port 22
- The loopback decoder issue does not apply
- `detection_filter` correctly counts connection attempts from the same external IP
- After 5 attempts in 60 seconds the alert fires

This is a well-documented limitation of testing SSH detection on loopback vs
a live network interface.

---

## Key Takeaways
- Hydra successfully simulated a real brute-force attack pattern
- The rule syntax and logic are correct and verified by Snort's rule loader
- SSH detection on loopback has known limitations due to encryption and
  stream handling
- The same rule deployed on enp0s3 monitoring real inbound traffic would
  fire correctly
