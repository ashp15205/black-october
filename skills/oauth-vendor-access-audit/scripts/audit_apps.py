#!/usr/bin/env python3
"""Flag risky OAuth apps / service principals from a JSON export.

Input: JSON list of objects:
{"name","publisher_verified"(bool),"owner"(str|null),"consent_type"("admin"|"user"),
 "multi_tenant"(bool),"permissions":[...],
 "credentials":[{"type","created"(YYYY-MM-DD),"expires"(YYYY-MM-DD)}],
 "last_sign_in"(YYYY-MM-DD|null)}
Usage: audit_apps.py apps.json [--today YYYY-MM-DD] [--json]
"""
import argparse, json, sys
from datetime import date

HIGH_RISK = ["directory.readwrite", "application.readwrite", "rolemanagement.readwrite",
             "mail.readwrite", "mail.send", "files.readwrite.all", "full_access",
             "user.readwrite.all", "group.readwrite.all", "sites.fullcontrol.all"]
UNUSED_DAYS, LONG_SECRET_DAYS, RECENT_CRED_DAYS = 90, 365, 30


def d(s):
    return date.fromisoformat(s) if s else None


def audit_app(app, today):
    flags, score = [], 0
    perms = [p.lower() for p in app.get("permissions", [])]
    hr = sorted({p for p in perms for h in HIGH_RISK if h in p})
    if hr:
        flags.append("HIGH_RISK_PERMISSIONS:" + ",".join(hr)); score += 3
    if "*" in perms or any(p.endswith(".all") and "read" not in p for p in perms):
        flags.append("BROAD_SCOPE"); score += 1
    if not app.get("owner"):
        flags.append("NO_OWNER"); score += 1
    if not app.get("publisher_verified"):
        flags.append("UNVERIFIED_PUBLISHER"); score += 1
    if app.get("consent_type") == "admin" and app.get("multi_tenant"):
        flags.append("ADMIN_CONSENT_MULTI_TENANT"); score += 2
    ls = d(app.get("last_sign_in"))
    if ls is None or (today - ls).days > UNUSED_DAYS:
        flags.append("UNUSED_OVER_90D"); score += 1
    for c in app.get("credentials", []):
        created, exp = d(c.get("created")), d(c.get("expires"))
        if created and (today - created).days <= RECENT_CRED_DAYS:
            flags.append("RECENT_CREDENTIAL_ADDED"); score += 2
        if created and exp and (exp - created).days > LONG_SECRET_DAYS:
            flags.append("LONG_LIVED_CREDENTIAL"); score += 1
        if exp and exp < today:
            flags.append("EXPIRED_CREDENTIAL_STILL_PRESENT"); score += 1
    risk = "HIGH" if score >= 5 else "MEDIUM" if score >= 3 else "LOW"
    return {"name": app["name"], "risk": risk, "score": score, "flags": sorted(set(flags))}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apps_json")
    ap.add_argument("--today", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    today = d(a.today) if a.today else date.today()
    try:
        with open(a.apps_json) as fh:
            apps = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"error: cannot read input: {e}")
    if not isinstance(apps, list):
        sys.exit("error: input must be a JSON list")
    res = sorted((audit_app(x, today) for x in apps), key=lambda r: -r["score"])
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print("| App | Risk | Score | Flags |\n|---|---|---|---|")
        for r in res:
            print(f"| {r['name']} | {r['risk']} | {r['score']} | {'; '.join(r['flags']) or '-'} |")


if __name__ == "__main__":
    main()
