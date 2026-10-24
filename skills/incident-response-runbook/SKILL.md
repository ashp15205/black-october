---
name: incident-response-runbook
description: Run or draft incident response for suspected breaches, ransomware, data leaks or compromised systems. Use whenever the user reports a security incident, ransomware, leaked data, suspicious activity, or asks for an IR plan, containment steps, evidence collection, or breach notification text.
---

# Incident Response Runbook

## Triage (first questions, ask max 3 if unknown)
What was observed, which systems/data, is it ongoing.

## Phases
1. Contain: isolate affected hosts (network, not power-off), disable compromised accounts, revoke tokens/sessions, block IOCs, preserve volatile evidence first.
2. Preserve evidence: logs, disk/memory images, timeline notes, hashes; keep chain of custody.
3. Scope: initial access vector, lateral movement, persistence, data accessed/exfiltrated, accounts and systems touched.
4. Eradicate: remove persistence, patch the entry point, rotate all credentials/keys/secrets on affected systems, rebuild from known-good where unsure.
5. Recover: restore from clean, verified backups; monitor closely for re-entry.
6. Notify: legal/privacy counsel, regulators and affected individuals per jurisdiction (e.g. India CERT-In 6-hour reporting, DPDP, GDPR 72h, sector rules), insurers, law enforcement. Verify current deadlines via web search before stating them.
7. Review: root cause, timeline, control gaps, owners and dates for fixes.

## Ransomware extras
Don't pay by default; check for decryptors, confirm backup integrity before restore, assume data theft if a leak-site listing exists, hunt for initial-access-broker tooling.

## Template
Use `assets/timeline-template.md` for the incident timeline and decision log.

## Output
Prioritized action checklist (now / 24h / this week), a timeline template, and draft notification text when asked. Mark assumptions clearly.
