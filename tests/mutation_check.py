#!/usr/bin/env python3
"""Mutation smoke test: break each script in a known way and confirm the unit tests catch it.
Run: python tests/mutation_check.py  (exit 0 only if every mutant is killed)"""
import os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUTANTS = [
    ("skills/patch-triage/scripts/triage.py", "p = max(p - 1, 0)", "p = p"),
    ("skills/patch-triage/scripts/triage.py", 'elif exposed and sev == "critical":', 'elif exposed and sev == "never":'),
    ("skills/patch-triage/scripts/triage.py", '3: "next patch cycle"', '3: "never"'),
    ("skills/cert-inventory-migration/scripts/cert_audit.py", "key.key_size < 2048", "key.key_size < 512"),
    ("skills/cert-inventory-migration/scripts/cert_audit.py", "end < now", "end < now - now + now.replace(year=1999)"),
    ("skills/cert-inventory-migration/scripts/cert_audit.py", 'any(f.startswith("DISTRUSTED")', 'any(f.startswith("NOPE")'),
    ("skills/oauth-vendor-access-audit/scripts/audit_apps.py", "score >= 5", "score >= 50"),
    ("skills/oauth-vendor-access-audit/scripts/audit_apps.py", "UNUSED_DAYS, LONG_SECRET_DAYS, RECENT_CRED_DAYS = 90, 365, 30", "UNUSED_DAYS, LONG_SECRET_DAYS, RECENT_CRED_DAYS = 9000, 365, 30"),
    ("skills/security-config-code-review/scripts/scan.py", '"scan:ignore" in line', '"zzz" in line'),
    ("skills/security-config-code-review/scripts/scan.py", r'AKIA[0-9A-Z]{16}', r'AKIB[0-9A-Z]{16}'),
    ("skills/security-config-code-review/scripts/scan.py", "verify\\s*=\\s*False", "verify\\s*=\\s*Nope"),
]
killed = 0
for rel, old, new in MUTANTS:
    tmp = tempfile.mkdtemp(); dst = os.path.join(tmp, "repo")
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    p = os.path.join(dst, rel); s = open(p).read()
    if old not in s:
        print(f"SKIP (pattern missing): {rel}: {old}"); sys.exit(2)
    open(p, "w").write(s.replace(old, new, 1))
    r = subprocess.run([sys.executable, "-m", "unittest", "tests.test_scripts"], cwd=dst, capture_output=True, text=True)
    ok = r.returncode != 0; killed += ok
    print(("KILLED  " if ok else "SURVIVED") + f" {rel.split('/')[1]}: {old[:50]}")
    shutil.rmtree(tmp)
print(f"{killed}/{len(MUTANTS)} mutants killed"); sys.exit(0 if killed == len(MUTANTS) else 1)
