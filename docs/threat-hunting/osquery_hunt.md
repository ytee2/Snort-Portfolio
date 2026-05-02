# Threat Hunting Report: OSQuery System Investigation

## Overview
This document details a proactive threat hunting exercise conducted on the
Kali Linux lab machine using OSQuery 5.12.1. The goal was to investigate
the system for indicators of compromise (IOCs) across four key areas:
running processes, network connections, file system changes, and user accounts.

Threat hunting differs from reactive detection tools like Snort — instead of
waiting for an alert to fire, the analyst proactively queries the system
looking for anomalies that may indicate malicious activity that has bypassed
signature-based detection.

---

## Tool Used
- **OSQuery 5.12.1** — open-source endpoint visibility tool that exposes OS
  data as queryable SQL tables. Used by enterprise SOC teams at Facebook,
  Airbnb, and many Fortune 500 companies.

---

## Hunt 1 — Running Processes

### Query
```sql
SELECT pid, name, path, cmdline FROM processes LIMIT 20;
```

### What We Were Looking For
- Processes running from suspicious locations (`/tmp`, `/dev/shm`, `/var/tmp`)
- Processes with no path (common in memory-resident malware)
- Processes with obfuscated or encoded command line arguments
- Unexpected processes masquerading as legitimate system tools

### Findings
All running processes were legitimate and expected:
- Elasticsearch (Java JVM) running from `/usr/share/elasticsearch/`
- Kibana, Logstash running from standard installation paths
- System processes: systemd, dbus-daemon, pipewire, lightdm
- No processes found running from `/tmp` or `/dev/shm`
- No processes with missing or suspicious paths

### Verdict
**No indicators of compromise found.** System process list is consistent
with a standard Kali Linux installation running the ELK Stack.

---

## Hunt 2 — Network Connections

### Query
```sql
SELECT pid, local_address, local_port, remote_address, remote_port, state
FROM process_open_sockets WHERE state = 'ESTABLISHED' LIMIT 20;
```

### What We Were Looking For
- Connections to unknown external IP addresses
- Connections on unusual ports (not 80, 443, 22)
- Multiple connections to the same external IP (beaconing behaviour)
- Connections from unexpected processes

### Findings
Most connections were internal ELK Stack traffic on port 9200. One external
connection was identified:

| Source | Destination | Port | Assessment |
|--------|-------------|------|------------|
| 10.0.2.15:58304 | 34.72.239.183 | 443 | Google Cloud — likely Elasticsearch telemetry |

All other connections were loopback (127.0.0.1) ELK internal communication.

### Verdict
**One external connection noted** to `34.72.239.183:443`. Verified as Google
Cloud infrastructure likely used by Elasticsearch for telemetry. In a
production environment this would be investigated further by checking which
process owns the connection and whether outbound telemetry should be disabled.

---

## Hunt 3 — Listening Ports

### Query
```sql
SELECT pid, local_address, local_port, protocol
FROM process_open_sockets WHERE state = 'LISTEN' LIMIT 20;
```

### What We Were Looking For
- Unexpected backdoor ports opened by malware
- Services listening on all interfaces (0.0.0.0) that should be localhost only
- Unknown ports with no associated legitimate process

### Findings
| Port | Service | Assessment |
|------|---------|------------|
| 5601 | Kibana | Expected — web UI |
| 9200 | Elasticsearch | Expected — API |
| 9300 | Elasticsearch | Expected — cluster comms |
| 9600 | Logstash | Expected — monitoring API |

### Verdict
**No unexpected listening ports found.** All 4 ports are accounted for by
the ELK Stack installation. No backdoor ports detected.

---

## Hunt 4 — Recently Modified System Files

### Query
```sql
SELECT path, mtime, size FROM file
WHERE path LIKE '/etc/%'
AND mtime > (SELECT unix_time - 86400 FROM time) LIMIT 20;
```

### What We Were Looking For
- Modifications to `/etc/passwd` or `/etc/shadow` (user account tampering)
- Changes to `/etc/crontab` or `/etc/cron.d/` (persistence via scheduled tasks)
- Modifications to `/etc/sudoers` (privilege escalation)
- Any unexpected changes to configuration files

### Findings
| File | Reason for Change | Risk |
|------|------------------|------|
| `/etc/default/` | OSQuery package installation | Low |
| `/etc/init.d/` | OSQuery package installation | Low |
| `/etc/mtab` | Normal mount table updates | None |
| `/etc/resolv.conf` | Network manager DNS update | None |

### Verdict
**No suspicious file modifications found.** All changes are explained by
the OSQuery installation performed during this exercise and normal system
operation.

---

## Hunt 5 — User Accounts

### Query
```sql
SELECT username, uid, gid, shell, directory FROM users;
```

### What We Were Looking For
- Unknown user accounts not present in a standard installation
- Accounts with uid 0 (root privileges) that should not have them
- Service accounts that have been given a login shell (potential backdoor)
- Accounts with home directories in unusual locations

### Findings
Two accounts have active login shells:
| Username | UID | Shell | Assessment |
|----------|-----|-------|------------|
| root | 0 | /usr/bin/zsh | Expected — system root |
| kali | 1000 | /usr/bin/zsh | Expected — primary user |
| postgres | 126 | /bin/bash | Worth noting — database service with bash shell |

All other accounts use `/usr/sbin/nologin` or `/bin/false` confirming
they cannot be used for interactive login.

### Verdict
**No unauthorised accounts found.** The `postgres` account having a bash
shell is standard for PostgreSQL on Debian-based systems. In a production
environment this would be documented and reviewed against the system baseline.

---

## Summary

| Hunt Area | Finding | Verdict |
|-----------|---------|---------|
| Running Processes | All legitimate, known paths | Clean |
| Network Connections | One external connection to Google Cloud | Investigate further |
| Listening Ports | Only ELK Stack ports | Clean |
| File Modifications | Only from OSQuery install + system | Clean |
| User Accounts | Only root and kali have login shells | Clean |

---

## Key Learning

This exercise demonstrates the difference between reactive and proactive
security. Snort waited for attack traffic to match a rule — OSQuery lets
you ask questions about the system state at any time, without needing an
attack to trigger first.

In a real SOC investigation, these queries would be run immediately after
an alert fires to understand the full system context — what processes were
running, what connections existed, and whether any persistence mechanisms
were in place.

---

## Queries Reference
All queries used in this hunt are reusable and can be scheduled using
OSQuery's daemon mode (`osqueryd`) to run automatically and ship results
to a SIEM for continuous monitoring.

```sql
-- Process hunt
SELECT pid, name, path, cmdline FROM processes;

-- Network connection hunt  
SELECT pid, local_address, local_port, remote_address, remote_port, state
FROM process_open_sockets WHERE state = 'ESTABLISHED';

-- Listening port hunt
SELECT pid, local_address, local_port, protocol
FROM process_open_sockets WHERE state = 'LISTEN';

-- File modification hunt (last 24 hours)
SELECT path, mtime, size FROM file
WHERE path LIKE '/etc/%'
AND mtime > (SELECT unix_time - 86400 FROM time);

-- User account hunt
SELECT username, uid, gid, shell, directory FROM users;
```
