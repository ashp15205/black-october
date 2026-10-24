#!/usr/bin/env python3
"""Run all eval cases and write evals/results/benchmark.json.
Script cases execute the real scripts against generated fixtures and grade programmatically.
LLM cases grade a saved output file (produced by Claude following the SKILL.md) with
regex/keyword checks. Run from the repo root: python evals/run_evals.py"""
import contextlib, io, json, os, re, sys, tempfile, importlib.util, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import fixtures


def load(skill, script):
    p = os.path.join(ROOT, "skills", skill, "scripts", script)
    spec = importlib.util.spec_from_file_location(script[:-3], p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def run(mod, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try: rc = mod.main(argv)
        except SystemExit as e: rc = e.code
    return rc, buf.getvalue()


def w(p, t):
    with open(p, "w") as f: f.write(t)


def script_checks():
    T = load("patch-triage", "triage.py"); C = load("cert-inventory-migration", "cert_audit.py")
    O = load("oauth-vendor-access-audit", "audit_apps.py"); S = load("security-config-code-review", "scan.py")
    d = tempfile.mkdtemp(); R = {}
    csv_ = f"{d}/v.csv"; fixtures.make_triage_csv(csv_)
    _, md = run(T, [csv_]); _, js = run(T, [csv_, "--format", "json"]); tj = {x["cve"]: x for x in json.loads(js)}
    R["triage-1"] = {"first_row_is_P0": md.splitlines()[2].split("|")[4].strip() == "P0",
                     "markdown_header": md.startswith("| CVE |"),
                     "low_internal_is_P3": tj["CVE-E"]["priority"] == "P3",
                     "edge_bump_applied": tj["CVE-G"]["priority"] == "P2"}
    bad = f"{d}/b.csv"; w(bad, ",".join(T.REQUIRED) + "\nx,a,p,no,no,urgent,yes,no\n")
    rc, _ = run(T, [bad]); R["triage-2"] = {"errors_clearly_on_bad_input": "invalid severity" in str(rc)}
    cd = f"{d}/certs"; fixtures.make_certs(cd)
    rc, js = run(C, [cd, "--distrust", "Bad Test Root", "--json"]); cj = json.loads(js)
    fl = lambda n: {f for r in cj if r["file"].endswith(n) for f in r["flags"]}
    R["cert-1"] = {"distrusted_flagged": "DISTRUSTED_ISSUER" in fl("leaf_bad.pem"),
                   "clean_not_flagged": fl("leaf_good.pem") == set(), "exit_code_1": rc == 1,
                   "expired_and_weak_detected": "EXPIRED" in fl("expired.pem") and "WEAK_RSA" in fl("weak_rsa.pem")}
    rc, _ = run(C, [f"{cd}/leaf_good.pem", "--distrust", "Bad Test Root"]); R["cert-2"] = {"exit_code_0": rc == 0}
    ap = f"{d}/apps.json"; fixtures.make_apps_json(ap)
    _, js = run(O, [ap, "--today", "2026-10-24", "--json"]); oj = json.loads(js); on = {x["name"]: x for x in oj}
    R["oauth-1"] = {"msp_high": on["MSP Remote Tool"]["risk"] == "HIGH", "hr_low": on["HR Portal"]["risk"] == "LOW",
                    "stale_flags": {"UNUSED_OVER_90D", "EXPIRED_CREDENTIAL_STILL_PRESENT"} <= set(on["Old Sync"]["flags"]),
                    "sorted_by_risk": [x["score"] for x in oj] == sorted([x["score"] for x in oj], reverse=True)}
    bj = f"{d}/bad.json"; w(bj, "{nope"); rc, _ = run(O, [bj]); R["oauth-2"] = {"errors_clearly_on_bad_input": "cannot read input" in str(rc)}
    v, c = f"{d}/v", f"{d}/c"; fixtures.make_code_tree(v, True); fixtures.make_code_tree(c, False)
    _, js = run(S, [v, "--json"]); sj = json.loads(js)
    exp = {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY", "WEAK_RANDOM_FOR_SECRET", "WEAK_HASH",
           "TLS_VERIFY_DISABLED", "DEBUG_ENABLED", "OPEN_TO_WORLD", "PERMISSIVE_CHMOD"}
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    R["code-1"] = {"finds_9_rule_classes": exp <= {x["rule"] for x in sj},
                   "critical_first": sj[0]["severity"] == "CRITICAL",
                   "fail_on_exit_1": run(S, [v, "--fail-on", "HIGH"])[0] == 1}
    _, js = run(S, [c, "--json"]); R["code-2"] = {"zero_findings": json.loads(js) == [],
                                                   "fail_on_exit_0": run(S, [c, "--fail-on", "LOW"])[0] == 0}
    return R


def has(t, *pats): return all(re.search(p, t, re.I) for p in pats)


LLM = {
    "has_contain_preserve_notify": lambda t: has(t, r"contain", r"preserve", r"notify"),
    "isolate_not_poweroff": lambda t: has(t, r"isolate", r"do not power off"),
    "backups_verified": lambda t: has(t, r"backup", r"verify|integrity"),
    "deadlines_marked_verify": lambda t: has(t, r"verify (current )?(deadline|requirement)|deadlines change: verify|verify the current"),
    "no_pay_default": lambda t: has(t, r"do not pay by default"),
    "assumptions_stated": lambda t: has(t, r"assumptions?:"),
    "logs_preserved": lambda t: has(t, r"(do not delete|preserve).*(log|object)|logs?"),
    "brief_sections": lambda t: has(t, r"\*\*summary", r"\*\*impact on you", r"\*\*actions", r"\*\*sources"),
    "impact_verdict": lambda t: has(t, r"affected|possibly|unknown"),
    "separates_vendor_claims": lambda t: has(t, r"vendor'?s? (statement|claim)|eMudhra'?s claim"),
    "has_sources": lambda t: has(t, r"\*\*sources:\*\*\s*\S+"),
    "no_unsupported_cve": lambda t: not re.search(r"CVE-\d{4}-\d+", t),
    "no_invented_fixed_version": lambda t: not re.search(r"14\.1-\d+\.\d+|fixed in \d", t) and has(t, r"verify|confirm"),
    "single_source_flagged": lambda t: has(t, r"single|one news report"),
}


def main():
    cases = json.load(open(os.path.join(ROOT, "evals", "evals.json")))["cases"]
    t0 = time.time(); sr = script_checks(); out = []
    for c in cases:
        if c["type"] == "script":
            res = sr[c["id"]]
        else:
            txt = open(os.path.join(ROOT, "evals", c["output"])).read()
            res = {a: bool(LLM[a](txt)) for a in c["assertions"]}
        assert set(res) == set(c["assertions"]), (c["id"], set(res) ^ set(c["assertions"]))
        out.append({"id": c["id"], "skill": c["skill"], "type": c["type"], "results": res,
                    "passed": sum(res.values()), "total": len(res)})
    P, N = sum(o["passed"] for o in out), sum(o["total"] for o in out)
    by = {}
    for o in out:
        b = by.setdefault(o["skill"], [0, 0]); b[0] += o["passed"]; b[1] += o["total"]
    bench = {"assertions_passed": P, "assertions_total": N, "pass_rate": round(P / N, 4),
             "by_skill": {k: {"passed": v[0], "total": v[1]} for k, v in by.items()},
             "cases": out, "seconds": round(time.time() - t0, 2)}
    json.dump(bench, open(os.path.join(ROOT, "evals", "results", "benchmark.json"), "w"), indent=2)
    for o in out:
        fails = [k for k, v in o["results"].items() if not v]
        print(f"{o['id']:<10} {o['passed']}/{o['total']} {'FAIL: ' + ','.join(fails) if fails else 'ok'}")
    print(f"TOTAL {P}/{N} ({bench['pass_rate']*100:.1f}%) in {bench['seconds']}s")
    return 0 if P == N else 1


if __name__ == "__main__":
    sys.exit(main())
