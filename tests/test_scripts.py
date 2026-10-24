import contextlib, io, json, os, subprocess, sys, tempfile, unittest, importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import fixtures


def load(skill, script):
    p = os.path.join(ROOT, "skills", skill, "scripts", script)
    spec = importlib.util.spec_from_file_location(script[:-3], p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m, p


def w(path, text):
    with open(path, "w") as f:
        f.write(text)


def run(mod, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            rc = mod.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, buf.getvalue()


class TestTriage(unittest.TestCase):
    def setUp(self):
        self.m, _ = load("patch-triage", "triage.py")
        self.d = tempfile.mkdtemp(); self.csv = f"{self.d}/v.csv"
        fixtures.make_triage_csv(self.csv)
        _, out = run(self.m, [self.csv, "--format", "json"])
        self.r = {x["cve"]: x for x in json.loads(out)}

    def test_exploited_exposed_edge_is_p0(self): self.assertEqual(self.r["CVE-A"]["priority"], "P0")
    def test_exploited_exposed_is_p0(self): self.assertEqual(self.r["CVE-B"]["priority"], "P0")
    def test_internal_high_is_p2(self): self.assertEqual(self.r["CVE-C"]["priority"], "P2")
    def test_exposed_high_edge_bumps_to_p1(self): self.assertEqual(self.r["CVE-D"]["priority"], "P1")
    def test_low_is_p3(self): self.assertEqual(self.r["CVE-E"]["priority"], "P3")
    def test_exploited_internal_is_p1(self): self.assertEqual(self.r["CVE-F"]["priority"], "P1")
    def test_edge_bumps_medium_to_p2(self): self.assertEqual(self.r["CVE-G"]["priority"], "P2")
    def test_exposed_critical_unexploited_is_p1(self): self.assertEqual(self.r["CVE-H"]["priority"], "P1")
    def test_deadline_p3(self): self.assertEqual(self.r["CVE-E"]["deadline"], "next patch cycle")
    def test_deadline_p1_p2(self):
        self.assertEqual(self.r["CVE-H"]["deadline"], "72 hours"); self.assertEqual(self.r["CVE-C"]["deadline"], "14 days")
    def test_deadline_p0(self): self.assertEqual(self.r["CVE-A"]["deadline"], "24 hours")
    def test_no_patch_mitigation(self): self.assertIn("mitigate", self.r["CVE-B"]["action"])
    def test_p0_edge_compromise_check(self): self.assertIn("compromise", self.r["CVE-A"]["action"])
    def test_sorted_p0_first(self):
        _, out = run(self.m, [self.csv, "--format", "json"])
        pr = [x["priority"] for x in json.loads(out)]; self.assertEqual(pr, sorted(pr))
    def test_markdown_output(self):
        _, out = run(self.m, [self.csv]); self.assertTrue(out.startswith("| CVE |"))
    def test_missing_column_errors(self):
        bad = f"{self.d}/bad.csv"; w(bad, "cve,asset\nx,y\n")
        rc, _ = run(self.m, [bad]); self.assertIn("missing columns", str(rc))
    def test_invalid_severity_errors(self):
        bad = f"{self.d}/bad2.csv"
        w(bad, ",".join(self.m.REQUIRED) + "\nx,a,p,no,no,urgent,yes,no\n")
        rc, _ = run(self.m, [bad]); self.assertIn("invalid severity", str(rc))


class TestCerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m, cls.script = load("cert-inventory-migration", "cert_audit.py")
        cls.d = tempfile.mkdtemp(); fixtures.make_certs(cls.d)
        _, out = run(cls.m, [cls.d, "--distrust", "Bad Test Root", "--json"])
        cls.res = json.loads(out)

    def flags(self, name):
        return {f for r in self.res if r["file"].endswith(name) for f in r["flags"]}

    def test_distrusted_issuer_flagged(self): self.assertIn("DISTRUSTED_ISSUER", self.flags("leaf_bad.pem"))
    def test_good_leaf_clean(self): self.assertEqual(self.flags("leaf_good.pem"), set())
    def test_expired(self): self.assertIn("EXPIRED", self.flags("expired.pem"))
    def test_expires_soon(self): self.assertIn("EXPIRES_SOON", self.flags("soon.pem"))
    def test_weak_rsa(self): self.assertIn("WEAK_RSA", self.flags("weak_rsa.pem"))
    def test_weak_signature(self): self.assertIn("WEAK_SIGNATURE", self.flags("sha1.pem"))
    def test_chain_cert_counted(self): self.assertEqual(sum(1 for r in self.res if r["file"].endswith("leaf_bad.pem")), 2)
    def test_exit_code_1_when_distrusted(self):
        rc, _ = run(self.m, [self.d, "--distrust", "Bad Test Root"]); self.assertEqual(rc, 1)
    def test_exit_code_0_when_clean(self):
        rc, _ = run(self.m, [f"{self.d}/leaf_good.pem", "--distrust", "Bad Test Root"]); self.assertEqual(rc, 0)
    def test_spki_hash_match(self):
        h = next(r["spki_sha256"] for r in self.res if r["file"].endswith("leaf_good.pem"))
        _, out = run(self.m, [f"{self.d}/leaf_good.pem", "--spki-hash", h, "--json"])
        self.assertIn("DISTRUSTED_SPKI", json.loads(out)[0]["flags"])
    def test_no_files_errors(self):
        rc, _ = run(self.m, [tempfile.mkdtemp()]); self.assertIn("no certificate files", str(rc))


class TestOAuth(unittest.TestCase):
    def setUp(self):
        self.m, _ = load("oauth-vendor-access-audit", "audit_apps.py")
        self.d = tempfile.mkdtemp(); self.f = f"{self.d}/apps.json"; fixtures.make_apps_json(self.f)
        _, out = run(self.m, [self.f, "--today", "2026-10-24", "--json"])
        self.r = {x["name"]: x for x in json.loads(out)}

    def test_msp_high(self): self.assertEqual(self.r["MSP Remote Tool"]["risk"], "HIGH")
    def test_msp_flags(self):
        f = " ".join(self.r["MSP Remote Tool"]["flags"])
        for k in ("HIGH_RISK_PERMISSIONS", "NO_OWNER", "UNVERIFIED_PUBLISHER",
                  "ADMIN_CONSENT_MULTI_TENANT", "RECENT_CREDENTIAL_ADDED", "LONG_LIVED_CREDENTIAL"):
            self.assertIn(k, f)
    def test_hr_low(self): self.assertEqual(self.r["HR Portal"]["risk"], "LOW")
    def test_old_sync_flags(self):
        f = self.r["Old Sync"]["flags"]
        self.assertIn("UNUSED_OVER_90D", f); self.assertIn("EXPIRED_CREDENTIAL_STILL_PRESENT", f)
    def test_sorted_by_score(self):
        _, out = run(self.m, [self.f, "--today", "2026-10-24", "--json"])
        s = [x["score"] for x in json.loads(out)]; self.assertEqual(s, sorted(s, reverse=True))
    def test_bad_json_errors(self):
        p = f"{self.d}/x.json"; w(p, "{nope")
        rc, _ = run(self.m, [p]); self.assertIn("cannot read input", str(rc))
    def test_non_list_errors(self):
        p = f"{self.d}/y.json"; w(p, "{}")
        rc, _ = run(self.m, [p]); self.assertIn("JSON list", str(rc))


class TestScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m, _ = load("security-config-code-review", "scan.py")
        cls.v, cls.c = tempfile.mkdtemp(), tempfile.mkdtemp()
        fixtures.make_code_tree(cls.v, True); fixtures.make_code_tree(cls.c, False)
        _, out = run(cls.m, [cls.v, "--json"]); cls.vr = json.loads(out)
        _, out = run(cls.m, [cls.c, "--json"]); cls.cr = json.loads(out)

    def rules(self): return {x["rule"] for x in self.vr}
    def test_all_expected_rules_found(self):
        exp = {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY", "WEAK_RANDOM_FOR_SECRET", "WEAK_HASH",
               "TLS_VERIFY_DISABLED", "DEBUG_ENABLED", "OPEN_TO_WORLD", "PERMISSIVE_CHMOD"}
        self.assertTrue(exp <= self.rules(), exp - self.rules())
    def test_js_math_random_token(self):
        self.assertTrue(any(x["file"].endswith("web.js") and x["rule"] == "WEAK_RANDOM_FOR_SECRET" for x in self.vr))
    def test_clean_tree_has_zero_findings(self): self.assertEqual(self.cr, [])
    def test_secrets_module_not_flagged(self):
        self.assertFalse(any(x["rule"] == "WEAK_RANDOM_FOR_SECRET" for x in self.cr))
    def test_sorted_critical_first(self):
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        lv = [order.index(x["severity"]) for x in self.vr]; self.assertEqual(lv, sorted(lv, reverse=True))
    def test_fail_on_exit_code(self):
        self.assertEqual(run(self.m, [self.v, "--fail-on", "HIGH"])[0], 1)
        self.assertEqual(run(self.m, [self.c, "--fail-on", "LOW"])[0], 0)
    def test_ignore_marker(self):
        d = tempfile.mkdtemp(); w(f"{d}/a.py", 'x = hashlib.md5(b"")  # scan:ignore\n')
        _, out = run(self.m, [d, "--json"]); self.assertEqual(json.loads(out), [])
    def test_missing_path_errors(self):
        rc, _ = run(self.m, ["/nonexistent/zzz"]); self.assertIn("path not found", str(rc))
    def test_line_numbers(self):
        self.assertTrue(all(isinstance(x["line"], int) and x["line"] >= 1 for x in self.vr))


    def test_exclude_dir(self):
        d = tempfile.mkdtemp(); os.makedirs(f"{d}/tests"); w(f"{d}/tests/a.py", "x = hashlib.md5(b'')\n")
        _, out = run(self.m, [d, "--json", "--exclude", "tests"]); self.assertEqual(json.loads(out), [])


class TestCLI(unittest.TestCase):
    def test_scripts_run_as_subprocess(self):
        d = tempfile.mkdtemp(); p = f"{d}/v.csv"; fixtures.make_triage_csv(p)
        s = os.path.join(ROOT, "skills/patch-triage/scripts/triage.py")
        r = subprocess.run([sys.executable, s, p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0); self.assertIn("P0", r.stdout)
        r = subprocess.run([sys.executable, s, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
