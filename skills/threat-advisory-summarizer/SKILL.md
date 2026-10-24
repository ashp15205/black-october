---
name: threat-advisory-summarizer
description: Turn threat advisories, CVE notices, CISA/vendor bulletins and security news into an "are we affected, what to do" brief for the user's stack. Use whenever the user shares or asks about a security advisory, breach news, new campaign or ransomware group, or asks for a security news roundup with actions.
---

# Threat Advisory Summarizer

## Inputs
Advisory text/URL or topic, plus the user's stack (products, vendors, cloud). If the stack is unknown, give a generic brief and list products to check.

## Steps
1. Fetch/search the primary source (CISA, vendor advisory, researcher write-up) and corroborate with one more; use the current date for recency.
2. Extract: what happened, affected products/versions, exploitation status, actor/group, IOCs, patches/mitigations, dates.
3. Map to the user's stack: Affected / Possibly / Not affected / Unknown.
4. Give actions ordered by urgency, with exact versions and settings.
5. Separate confirmed facts from vendor claims and speculation.

## Template
Use `assets/brief-template.md` for the output layout.

## Output
1. One-line summary
2. Impact on you (Affected / Not / Unknown)
3. Actions (now / 72h / later)
4. Key IOCs or log queries, if available
5. Sources
Keep it under one screen unless asked for more.
