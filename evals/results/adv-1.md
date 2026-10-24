# eMudhra intermediate CA key compromise (as of 2026-10-24)

**Summary:** Private keys for eight eMudhra intermediate CA certificates were derivable from the public certificates because of weak randomness; browsers and trust stores have moved to block them.

**Impact on you:** Affected if any TLS or code-signing certificate in your estate chains to eMudhra's affected roots/intermediates (including Sectigo cross-signed copies). Unknown until you run an inventory. Not affected if you use no eMudhra-issued certificates.

**Actions**
- Now (0-24h): inventory certificates chained to eMudhra; stop issuance from the affected root; apply browser/OS updates and trust-store changes.
- Within 72h: reissue about 30,000-certificate-scale estates from another trusted CA (ACME makes this fast), revoke old ones, re-sign code signed by the two affected code-signing intermediates.
- Later: add CAA records, automate lifecycle, keep a tested CA-swap runbook.

**Detection:** Check Certificate Transparency logs for certificates on your domains you did not request.

**Confidence:** Confirmed by Mozilla and Chrome root programs: keys compromised, trust removed/blocked. eMudhra's claim that its infrastructure was not breached and that no end-entity certificates were issued from the affected intermediates is the vendor's statement. As of Oct 21 no malicious use was confirmed. Google's decision on the remaining CA certificate was still pending.

**Sources:** The Hacker News (Oct 20, updated Oct 21); Google Security blog; Help Net Security (Oct 21).
