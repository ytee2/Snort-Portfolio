# Incident Report: HTTP Directory Traversal Detection

## Summary
Snort rule sid:9000006 did not generate alerts during testing. Investigation
revealed the rule requires HTTP traffic to be properly parsed by Snort's HTTP
inspector, which was not confirmed active during the test session.

## Detection Details
- **Rule:** `alert tcp any any -> any 80 (msg:"HTTP Directory Traversal Detected"; content:"../"; http_uri; sid:9000006; rev:1;)`
- **SID:** 9000006
- **Result:** No alerts generated

## What Was Observed
No entries for sid:9000006 were found in alert_fast.txt despite the simulation
command being run:
`curl "http://localhost/../etc/passwd"` (with python3 -m http.server 80 running)

## Why the Rule May Not Have Fired
The `http_uri` keyword tells Snort to only look inside the HTTP URI field after
the HTTP inspector has decoded the request. If Snort's HTTP inspector was not
processing traffic on port 80 at the time, the rule would never match even if
the packet contained `../`.

This is different from `content:"../"` alone, which searches the raw packet.
`http_uri` requires Snort to fully parse the HTTP layer first.

## Key Learning
Using application-layer keywords like `http_uri`, `http_header`, or `http_method`
requires the corresponding Snort inspector to be active. This is a common
troubleshooting point when rules appear to be written correctly but produce no alerts.

## Recommendations
- Verify HTTP inspector is enabled in snort.lua
- Test with raw content match first: remove `http_uri` and retest
- Re-run simulation and confirm curl request reaches the local server before
  assuming Snort is the issue
- Document results after re-testing
