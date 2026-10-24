# Publicly exposed storage bucket: action checklist (assumptions marked)

Assumptions: bucket held customer documents, exposure duration unknown, still public.

## Now: Contain
- Block public access on the bucket immediately; revoke any pre-signed URLs and rotate access keys tied to it.
- Do not delete objects or logs; preserve them as evidence.

## Preserve and scope
- Enable/pull access logs (CloudTrail data events, server access logs) to find who read what and from which IPs, and since when the bucket was public.
- Inventory the data types in the bucket (personal data, credentials, contracts).
- Search the web and paste sites for the data to check whether it has already been posted.

## Eradicate and recover
- Fix the root cause: account-level block-public-access, policy review, IaC guardrails.
- Rotate any secrets found inside the bucket.

## Notify (verify current deadlines before sending)
- Counsel and privacy officer decide on regulator and individual notification; verify the current deadline for your jurisdiction (GDPR 72h, CERT-In, DPDP, sector rules).

## Review
Document timeline and gaps using assets/timeline-template.md.
