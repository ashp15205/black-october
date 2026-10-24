#!/usr/bin/env python3
"""Deterministic patch prioritisation from a CSV of vulnerabilities.

Columns (header required, yes/no values case-insensitive):
cve,asset,product,exploited,internet_exposed,severity,patch_available,edge_device
severity: critical|high|medium|low
"""
import argparse, csv, json, sys

REQUIRED = ["cve", "asset", "product", "exploited", "internet_exposed",
            "severity", "patch_available", "edge_device"]
DEADLINE = {0: "24 hours", 1: "72 hours", 2: "14 days", 3: "next patch cycle"}


def yn(v):
    return str(v).strip().lower() in ("yes", "y", "true", "1")


def priority(row):
    exploited, exposed = yn(row["exploited"]), yn(row["internet_exposed"])
    sev = row["severity"].strip().lower()
    if exploited and exposed:
        p = 0
    elif exploited:
        p = 1
    elif exposed and sev == "critical":
        p = 1
    elif sev in ("critical", "high"):
        p = 2
    else:
        p = 3
    if yn(row["edge_device"]):
        p = max(p - 1, 0)
    return p


def action(row, p):
    if yn(row["patch_available"]):
        a = "Patch/upgrade"
    else:
        a = "No patch: mitigate (disable feature, restrict access, WAF/virtual patch) and monitor"
    if p == 0 and yn(row["edge_device"]):
        a += "; check logs for compromise, then rotate credentials"
    return a


def load(path):
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        missing = [c for c in REQUIRED if c not in (r.fieldnames or [])]
        if missing:
            sys.exit(f"error: missing columns: {', '.join(missing)}")
        rows = list(r)
    for i, row in enumerate(rows, start=2):
        if row["severity"].strip().lower() not in ("critical", "high", "medium", "low"):
            sys.exit(f"error: line {i}: invalid severity '{row['severity']}'")
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_file")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    a = ap.parse_args(argv)
    out = []
    for row in load(a.csv_file):
        p = priority(row)
        out.append({"cve": row["cve"], "asset": row["asset"], "product": row["product"],
                    "priority": f"P{p}", "deadline": DEADLINE[p], "action": action(row, p)})
    out.sort(key=lambda x: (x["priority"], x["cve"]))
    if a.format == "json":
        print(json.dumps(out, indent=2))
    else:
        print("| CVE | Asset | Product | Priority | Deadline | Action |")
        print("|---|---|---|---|---|---|")
        for o in out:
            print(f"| {o['cve']} | {o['asset']} | {o['product']} | {o['priority']} | {o['deadline']} | {o['action']} |")


if __name__ == "__main__":
    main()
