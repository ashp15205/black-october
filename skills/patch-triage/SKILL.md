---
name: patch-triage
description: Prioritize vulnerabilities and patches into an actionable remediation list. Use whenever the user shares CVEs, a scanner export, a security advisory, or asks what to patch first, even if they don't say "triage". Covers actively exploited flaws, edge devices (firewalls, VPNs, Citrix, Fortinet, Palo Alto), PHP, Oracle and similar.
---

# Patch Triage

## Inputs
CVE list, scanner export, advisory text, or asset list. If the asset inventory is missing, proceed with stated assumptions and list what to confirm.

## Steps
1. For each CVE, search the web for current status: actively exploited (CISA KEV, vendor advisory), exploit/PoC public, patch available, affected versions. Do not rely on memory for exploitation status.
2. Score priority:
   - P0: actively exploited AND internet-exposed or unauthenticated RCE/auth bypass. Fix in 24h.
   - P1: exploited or PoC public, or critical on exposed asset. Fix in 72h.
   - P2: critical/high, internal only, no known exploitation. Fix in 14 days.
   - P3: the rest. Next cycle.
3. Edge devices (VPN, firewall, gateway, load balancer) are bumped one level up.
4. For P0/P1 with no patch: give a mitigation (disable feature, WAF/virtual patch, restrict access, isolate).
5. For P0 edge flaws, add compromise checks: review logs for unknown sessions, new accounts, config changes, exfil tools (e.g. Rclone), then rotate credentials.

## Script (deterministic scoring)
Put findings in a CSV with columns `cve,asset,product,exploited,internet_exposed,severity,patch_available,edge_device` (yes/no; severity critical|high|medium|low) and run:
`python scripts/triage.py vulns.csv [--format json]`
Rules: exploited+exposed=P0; exploited=P1; exposed+critical=P1; critical/high=P2; else P3; edge device bumps one level up. Fill `exploited` from live sources (step 1), not memory. Use the script output as the table below.

## Output
Table: CVE | Asset/product | Exploited? | Exposure | Priority | Action | Deadline | Owner (blank if unknown).
Follow with "Assumptions" and "Verify" lists, kept brief.
