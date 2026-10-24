---
name: cert-inventory-migration
description: Find, assess and migrate TLS and code-signing certificates affected by a CA compromise, distrust, expiry or weak keys. Use whenever the user mentions a certificate authority incident (e.g. eMudhra), revoked or distrusted CAs, certificate replacement, Certificate Transparency checks, ACME migration, or crypto-agility.
---

# Certificate Inventory & Migration

## Inputs
Affected CA/intermediate names or SPKI hashes, domains list, cert exports, server/config details. Ask only for what blocks progress.

## Steps
1. Confirm the incident facts via web search (browser root program notices, CCADB/Bugzilla, CA statement): which roots/intermediates, which cert types (TLS vs code signing), distrust dates.
2. Inventory: list every cert with issuer chain, expiry, location, owner, issuance method (ACME/manual). Provide commands, e.g.:
   - `openssl s_client -connect host:443 -showcerts </dev/null`
   - `openssl x509 -in cert.pem -noout -issuer -subject -enddate -fingerprint`
   - CT lookup: crt.sh `?q=%25.example.com&output=json`
3. Flag any cert whose chain includes an affected CA (check intermediates and cross-signed copies).
4. Plan replacement:
   - Choose an alternative trusted CA; ACME-issued certs: change the ACME directory URL and re-issue.
   - Manual certs: generate new key + CSR, issue, deploy, verify chain, revoke old.
   - Code-signing: re-sign released binaries, notify consumers, rotate signing keys.
5. Check CT logs for unexpected certificates on your domains (possible forgery).
6. Verify: chain served is correct, OCSP/CRL status, no browser warnings, old certs revoked.
7. Long-term: automate lifecycle (ACME), CAA records restricting allowed CAs, expiry monitoring, a tested CA-swap runbook.

## Script (local PEM audit)
`python scripts/cert_audit.py PATH... --distrust "CA name substring" [--spki-hash HEX] [--json]`
Flags DISTRUSTED_ISSUER / DISTRUSTED_IN_CHAIN / DISTRUSTED_SPKI, EXPIRED, EXPIRES_SOON, WEAK_RSA, WEAK_SIGNATURE. Exit code 1 if any distrusted cert is found. Get the CA names and SPKI hashes from the incident notice (step 1). It cannot detect low-entropy keys by itself; rely on the CA's published list of affected keys.

## Output
Inventory table (cert | issuer | affected? | action | deadline), a step-ordered migration plan, and a verification checklist.
