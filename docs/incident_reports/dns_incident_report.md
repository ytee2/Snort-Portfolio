# Incident Report: DNS Flood Detection

## Summary
Snort rule sid:9000008 did not generate alerts during the DNS flood simulation.
The detection_filter threshold of 50 queries in 10 seconds was not met on the
loopback interface during testing with `dig`.

## Detection Details
- **Rule:** `alert udp any any -> any 53 (msg:"DNS Flood Detected"; detection_filter: track by_src, count 50, seconds 10; sid:9000008; rev:1;)`
- **SID:** 9000008
- **Result:** No alerts generated

## What Was Observed
No entries for sid:9000008 were found in alert_fast.txt.
Simulation command used:
`for i in {1..60}; do dig @127.0.0.1 evil.com; done`

## Why the Rule May Not Have Fired
`detection_filter` requires the threshold to be reached before any alert fires.
The rule is set to: 50 packets from the same source within 10 seconds.

Two likely reasons it did not fire:
1. The `dig` loop ran on the loopback interface but Snort may have been monitoring
   `enp0s3` — meaning the traffic was never seen by Snort at all
2. The loop may not have generated packets fast enough to hit 50 within 10 seconds,
   as `dig` waits for a response before sending the next query

## Key Learning
`detection_filter` is a powerful tool for reducing noise but it must be tuned
carefully. If the threshold is too high or the interface is wrong, legitimate
flood traffic will go undetected. Always verify the interface matches where the
simulated traffic actually travels.

## Recommendations
- Confirm Snort interface matches simulation interface (lo vs enp0s3)
- Lower threshold temporarily to `count 5, seconds 10` to verify rule fires at all
- Use `&` or `xargs` to parallelise dig queries and generate traffic faster
- Re-run and document updated results
