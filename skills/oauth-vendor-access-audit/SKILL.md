---
name: oauth-vendor-access-audit
description: Audit OAuth apps, service principals, API tokens and third-party/MSP/vendor access for excessive or risky permissions. Use whenever the user mentions supply-chain attacks, ConnectWise-style compromises, Microsoft 365/Entra app consent, Graph permissions, vendor access reviews, or token and secret rotation.
---

# OAuth & Vendor Access Audit

## Inputs
App/service principal export (Entra, Google Workspace, GitHub, Slack, etc.), vendor list, or audit logs. If none, give the commands/portals to export them.

## Steps
1. Enumerate: app name, publisher, owner, permissions/scopes, consent type (admin/user), credentials (secrets/certs, expiry), last sign-in, tenant-wide vs scoped.
2. Flag risk:
   - High: Directory.ReadWrite, Application.ReadWrite, RoleManagement, Mail.ReadWrite, full_access, offline_access with broad scopes.
   - Unused >90 days, no owner, unverified publisher, long-lived secrets, multi-tenant apps with admin consent.
   - Credentials added/changed recently (persistence indicator).
3. Vendor/MSP access: list accounts and delegated admin relationships; check MFA, conditional access, least privilege, expiry of access.
4. Detection hunts (give queries): credential or permission changes on apps, new service principals, role/group changes, bulk Graph/API calls, failed-logon spikes (password spraying).
5. Remediate: remove unused apps, rotate secrets/tokens, restrict user consent, require admin approval workflow, shorten token lifetime, scope vendor access, enable alerts.
6. If compromise suspected: revoke sessions/tokens, rotate all vendor-issued credentials, review changes since earliest suspicious date.

## Script (export analysis)
`python scripts/audit_apps.py apps.json [--today YYYY-MM-DD] [--json]`
Input is a JSON list with name, publisher_verified, owner, consent_type, multi_tenant, permissions, credentials[{type,created,expires}], last_sign_in. Output ranks apps HIGH/MEDIUM/LOW with flags. Convert the tenant export into this shape first; mention any fields you had to assume.

## Output
Findings table (app/vendor | risk | evidence | fix | priority), then a containment checklist if compromise is suspected.
