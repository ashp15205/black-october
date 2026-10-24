---
name: security-config-code-review
description: Review code, infrastructure and configuration for security weaknesses. Use whenever the user shares code, configs, Terraform, Docker/K8s files, cloud settings or repos and wants a security review, or mentions exposed interfaces, hardcoded secrets, weak crypto, bad randomness or entropy, insecure defaults, or leaked databases.
---

# Security Config & Code Review

## Checklist
- Secrets: hardcoded keys/tokens/passwords, secrets in repos/history, .env committed.
- Crypto: weak or non-CSPRNG randomness (e.g. Math.random, rand(), fixed seeds), low-entropy keys, outdated algorithms (MD5, SHA1, DES, RSA<2048), ECB mode, missing key rotation, custom key-generation scripts without verification.
- Exposure: public buckets/databases, admin/management ports open to internet, default credentials, debug endpoints, missing auth on APIs.
- Input handling: injection (SQL/command/template), SSRF, deserialization, path traversal, XSS, file upload.
- Authn/z: missing MFA, broad IAM roles, wildcard permissions, missing object-level checks.
- Supply chain: unpinned dependencies, install scripts, typosquat risk, unreviewed CI actions, no branch protection.
- Logging: no audit logs, secrets in logs, no alerting.
- Cloud/containers: root containers, privileged mode, open security groups, no encryption at rest/in transit.

## Steps
1. Read all provided files before judging.
2. List findings with severity (Critical/High/Medium/Low), location, why it matters, concrete fix (code or config snippet).
3. Note what was not reviewed.

## Script (first-pass scan)
`python scripts/scan.py PATH [--json] [--fail-on HIGH]`
Regex-based: secrets/keys, non-crypto randomness for secrets, weak hashes/ciphers, TLS verify off, 0.0.0.0/0 rules, debug on, chmod 777. Add `scan:ignore` on a line to suppress a confirmed false positive. Treat results as leads: read the code, confirm each finding, and add what the regexes cannot see (logic flaws, authz, injection).

## Output
Findings table (severity | location | issue | fix), then the top 3 fixes to do first. No speculative findings; mark uncertain ones as "verify".
