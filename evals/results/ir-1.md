# Ransomware on file servers: action checklist (assumptions marked)

Assumptions: ~40 hosts encrypted, no confirmed exfil yet, backups exist but untested.

## Now (0-1h): Contain
- Isolate affected hosts at the network layer (switch port/VLAN/EDR isolate). Do not power off: memory holds keys and artifacts.
- Disable the accounts used on the file servers and any domain admin that logged in recently; revoke sessions and tokens.
- Block known IOCs from the ransom note (contact addresses, hashes) at proxy/EDR.
- Take backups offline now so they cannot be encrypted.

## Next (1-24h): Preserve and scope
- Capture memory and disk images of 2-3 representative hosts; hash and log chain of custody.
- Pull AD, VPN, EDR, firewall logs. Find the earliest suspicious event, the entry vector (exposed VPN/firewall, phished credential, vendor access) and lateral movement.
- Assume data theft until proven otherwise; check for Rclone/MEGA/large outbound transfers and for a leak-site listing.

## Eradicate and recover
- Remove persistence, patch the entry point, rotate all credentials, keys and secrets reachable from affected systems.
- Do not pay by default; check for public decryptors, involve counsel and law enforcement before any payment discussion.
- Verify backup integrity and scan backups for malware before restoring; restore to a clean segment and monitor for re-entry.

## Notify (verify current deadlines before sending)
- Legal/privacy counsel, insurer, and regulators per jurisdiction (e.g. CERT-In in India, GDPR 72h, sector rules). Deadlines change: verify the current requirement for your location first.
- Affected individuals if personal data is confirmed involved.

## Review
Root cause, timeline (use assets/timeline-template.md), control gaps with owners and dates.
