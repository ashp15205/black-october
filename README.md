# Claude Security Skills

**Six tested Claude Agent Skills for security teams: patch triage, certificate/CA migration, OAuth and vendor access audits, incident response runbooks, code and config security review, and threat-advisory briefs.**

![tests](https://img.shields.io/badge/unit%20tests-46%20passing-brightgreen) ![evals](https://img.shields.io/badge/eval%20assertions-40%2F40-brightgreen) ![mutants](https://img.shields.io/badge/mutants%20killed-11%2F11-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue) ![python](https://img.shields.io/badge/python-3.10%2B-blue)

Works with Claude.ai, Claude Code and any client that supports [Agent Skills](https://docs.claude.com) (`SKILL.md` folders). Dependency footprint: Python 3 plus `cryptography` (only for the certificate script).

---

## Why this exists

October 2026 showed the same failure patterns again and again: exposed edge devices exploited before patching, a certificate authority whose key-generation script produced guessable private keys, supply-chain access through over-privileged vendor OAuth apps, ransomware via initial-access brokers, and attackers using AI to move faster than defenders.

A skill cannot detect or block attacks. It makes Claude **consistent and faster at the repeatable work around prevention**: triaging what to patch first, finding every certificate affected by a CA incident, auditing app permissions, running an incident without forgetting steps, reviewing code for the usual mistakes, and turning advisories into "are we affected, what do we do".

Each skill pairs a written procedure (`SKILL.md`) with a **deterministic Python helper** where the task can be automated, so results are reproducible and unit-tested rather than left to model judgment.

## Who it is for

- Security engineers, SOC and blue-team analysts, and incident responders
- IT and platform admins who own patching, certificates and SaaS/OAuth access
- DevSecOps and developers who want a security first pass on code and config
- Small teams without a dedicated security staff who still need a repeatable process
- MSPs and vendor-risk owners reviewing third-party access

## The skills

| Skill | Problem it addresses | Helper script | Output |
|---|---|---|---|
| [`patch-triage`](skills/patch-triage) | Too many CVEs, unclear order; exploited edge devices (VPN, firewall, Citrix, PHP) | `triage.py` | P0-P3 table with deadlines and mitigations |
| [`cert-inventory-migration`](skills/cert-inventory-migration) | CA compromise/distrust, weak or expiring certificates | `cert_audit.py` | Flagged cert inventory, migration plan, verification checklist |
| [`oauth-vendor-access-audit`](skills/oauth-vendor-access-audit) | Supply-chain and OAuth abuse, over-privileged vendor/MSP apps | `audit_apps.py` | Ranked app risk table, containment steps |
| [`incident-response-runbook`](skills/incident-response-runbook) | Ransomware, leaks, suspected breaches | template | Phased action checklist, timeline, notification steps |
| [`security-config-code-review`](skills/security-config-code-review) | Hardcoded secrets, weak randomness/crypto, exposed config | `scan.py` | Severity-ranked findings with fixes |
| [`threat-advisory-summarizer`](skills/threat-advisory-summarizer) | Advisory overload, unclear impact | template | One-screen "affected? actions" brief |

## Install

**Claude.ai:** download the `.skill` files from [`releases/`](releases) and upload them in Claude's skills settings (menu names may change; check Anthropic's current docs).

**Claude Code:** copy the skill folders.
```bash
git clone https://github.com/ashp15205/claude-security-skills.git
cd claude-security-skills
mkdir -p ~/.claude/skills            # personal; use ./.claude/skills for one project
cp -r skills/* ~/.claude/skills/
pip install -r requirements.txt      # only needed for cert_audit.py
```

## How to use each skill

Skills trigger from your request. Example prompts:

**patch-triage**
> "Here is our scanner export. What do we patch first? Treat the VPN gateways as internet-facing."

Or run the helper directly:
```bash
python skills/patch-triage/scripts/triage.py vulns.csv --format json
# CSV columns: cve,asset,product,exploited,internet_exposed,severity,patch_available,edge_device
```
Rules: exploited and exposed = P0 (24h); exploited = P1 (72h); exposed and critical = P1; critical/high = P2 (14d); else P3; edge devices move up one level. Claude looks up exploitation status from live sources before filling the CSV.

**cert-inventory-migration**
> "A CA we use just had a key compromise. Find our affected certificates and plan the reissue."
```bash
python skills/cert-inventory-migration/scripts/cert_audit.py ./certs --distrust "CA Name" --spki-hash <hex>
# exit code 1 if anything chains to a distrusted CA
```
Flags: `DISTRUSTED_ISSUER`, `DISTRUSTED_IN_CHAIN`, `DISTRUSTED_SPKI`, `EXPIRED`, `EXPIRES_SOON`, `WEAK_RSA`, `WEAK_SIGNATURE`. It cannot detect low-entropy keys by itself; use the CA's published affected-key list.

**oauth-vendor-access-audit**
> "Audit our Entra app registrations after the ConnectWise-style supply-chain news."
```bash
python skills/oauth-vendor-access-audit/scripts/audit_apps.py apps.json --today 2026-10-24
```
Flags high-risk scopes, no owner, unverified publisher, admin-consented multi-tenant apps, unused apps, recently added or long-lived credentials.

**incident-response-runbook**
> "Ransomware encrypted about 40 file servers. What do we do right now?"

Returns a phased plan (contain, preserve, scope, eradicate, recover, notify, review) with stated assumptions, and tells you to verify current legal deadlines rather than quoting them from memory.

**security-config-code-review**
> "Review this repo for security problems."
```bash
python skills/security-config-code-review/scripts/scan.py . --exclude tests --fail-on HIGH
```
Heuristic regex pass for secrets, private keys, non-cryptographic randomness used for tokens, weak hashes/ciphers, disabled TLS verification, `0.0.0.0/0` rules, debug mode, `chmod 777`. Add `scan:ignore` to a line to suppress a confirmed false positive. Not a replacement for SAST or secret-scanning products.

**threat-advisory-summarizer**
> "Summarize this CISA advisory for a team running NetScaler 14.1."

Produces a one-screen brief: summary, impact on you, actions by urgency, detection, confidence (confirmed vs vendor claim vs speculation), sources.

## Benchmarks

Run it yourself in under a second: `python evals/run_evals.py`

| Check | Result |
|---|---|
| Unit tests (`tests/test_scripts.py`) | **46 / 46 pass**, run with `-W error::ResourceWarning` |
| Eval assertions (`evals/evals.json`, 12 cases, 2 per skill) | **40 / 40 pass** (20 on script cases, 20 on saved Claude outputs) |
| Mutation smoke test (`tests/mutation_check.py`) | **11 / 11 mutants killed** (a first run exposed 2 survivors; tests were added to close them) |
| Dogfood scan of this repo with `scan.py --fail-on LOW` (tests/ excluded) | 0 findings |
| `quick_validate.py` on all 6 skills | all valid |
| Runtime of full eval suite | about 0.2-0.4 s |

Per skill, eval assertions passed: patch-triage 5/5, cert-inventory-migration 5/5, oauth-vendor-access-audit 5/5, security-config-code-review 5/5, incident-response-runbook 10/10, threat-advisory-summarizer 10/10 (see `evals/results/benchmark.json`).

### What these numbers do and do not show

- **Script cases** execute the real scripts on fixtures generated at runtime and are graded by code. Strongest evidence.
- **LLM cases** (incident response, advisory briefs) grade saved outputs with keyword/regex checks (required sections, "verify deadlines", no invented CVE numbers or fixed versions). Those outputs were written by Claude following the `SKILL.md` in the same session that wrote the checks, so this is a **structure and guardrail check, not an independent quality evaluation**. Read the outputs in `evals/results/` yourself.
- **No baseline comparison**: there was no with-skill vs without-skill A/B run and no independent human or model grader.
- The scanner and certificate checks are **heuristics**. Expect false positives and false negatives; the mutation test shows the tests detect regressions, not that the rules catch every real-world issue.
- Fixtures are synthetic. The GitHub Actions workflow in `.github/workflows/test.yml` mirrors the local commands but had not been run on GitHub when this was written.

## Repository layout

```
skills/<skill>/SKILL.md        procedure Claude follows (frontmatter + steps)
skills/<skill>/scripts/        deterministic helpers (triage, cert_audit, audit_apps, scan)
skills/<skill>/assets/         output templates (IR timeline, advisory brief)
tests/                         unit tests, runtime fixtures, mutation check
evals/                         eval cases, saved outputs, runner, benchmark.json
releases/                      packaged .skill files for upload
docs/github-about.md           suggested repo description and topics
```

## Reference incidents (public reporting, Oct 2026)

These informed the skill design; verify details against primary sources.
- eMudhra intermediate CA key compromise: [The Hacker News](https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html), [Google Security blog](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/), [Help Net Security](https://www.helpnetsecurity.com/2026/10/21/emudhra-certificates-private-keys-compromised/)
- AI pentest tooling used in ConnectWise-linked tenant attacks: [SecurityWeek](https://securityweek.com/china-apt-uses-ai-pentest-tool-artex-in-connectwise-attacks)
- Edge device campaign (Fortinet, Palo Alto) tied to ransomware affiliates: [The Hacker News](https://thehackernews.com/2026/10/hackers-breach-enterprise-firewalls-and.html)

## FAQ

**Can a Claude skill prevent cyberattacks?** No. Prevention comes from controls such as patching, phishing-resistant MFA, least privilege, backups and monitoring. These skills speed up and standardize the analysis and response work around them.

**Do the skills send my data anywhere?** The scripts run locally and make no network calls. Claude itself may search the web for current exploitation status and advisories when a skill tells it to.

**Is it legal advice?** No. Notification deadlines vary by jurisdiction and change; the runbook tells Claude to verify them and you should involve counsel.

**Can I add my own skill?** Yes, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Keywords

Claude skills, Claude Code skills, Agent Skills, SKILL.md, cybersecurity automation, patch prioritization, vulnerability management, CISA KEV, certificate authority compromise, PKI incident response, certificate migration, OAuth app audit, Entra ID, supply-chain security, incident response runbook, ransomware response, secrets detection, secure code review, threat advisory summary, blue team.

## License

MIT. See [LICENSE](LICENSE).
