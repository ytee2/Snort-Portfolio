# Incident Report: TCP SYN Scan Detection

## Summary
A TCP SYN scan was detected, indicating reconnaissance activity intended to
identify open ports and services. No exploitation was observed.

---

## Detection
- Tool: Snort 3
- Rule SID: 9000004
- Alert Type: TCP SYN Scan

---

## Findings
- Single source IP observed
- Multiple destination ports targeted
- Activity occurred in a short time window
- No follow-on attack activity detected

---

## Severity Assessment
Medium – reconnaissance activity with potential to lead to exploitation.

---

## Recommendations
- Close unused ports or disable unnecessary services
- Restrict access to exposed services using firewall rules
- Monitor for repeated scanning attempts

---

## Final Assessment
The activity represents early-stage attack behavior. While no compromise occurred,
continued monitoring and hardening are recommended.
