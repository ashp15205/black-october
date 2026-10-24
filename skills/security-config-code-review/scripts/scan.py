#!/usr/bin/env python3
"""Lightweight regex security scanner for source and config files.

Usage: scan.py PATH [--json] [--fail-on LEVEL]
Detects: hardcoded secrets/private keys, non-cryptographic randomness used for
secrets, weak hashes/ciphers, TLS verification disabled, world-open network
rules, debug mode, permissive chmod. A heuristic first pass, not a replacement
for SAST/secret-scanning tools; findings need manual confirmation.
"""
import argparse, json, os, re, sys

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh", ".yml",
        ".yaml", ".json", ".tf", ".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".txt"}
SECRETISH = r"(token|secret|key|password|passwd|nonce|salt|session|otp)"
RULES = [
    ("CRITICAL", "PRIVATE_KEY", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    ("CRITICAL", "AWS_ACCESS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
    ("CRITICAL", "GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("HIGH", "HARDCODED_SECRET",
     r"""(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["'][^"'\s$\{]{8,}["']"""),
    ("HIGH", "WEAK_RANDOM_FOR_SECRET",
     r"(?i)(Math\.random\(|\brandom\.(random|randint|choice|randrange)\(|\brand\(\)|\bmt_rand\().*" + SECRETISH),
    ("HIGH", "WEAK_RANDOM_FOR_SECRET",
     r"(?i)" + SECRETISH + r".*(Math\.random\(|\brandom\.(random|randint|choice|randrange)\(|\brand\(\)|\bmt_rand\()"),
    ("HIGH", "TLS_VERIFY_DISABLED",
     r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0))"),
    ("HIGH", "OPEN_TO_WORLD", r"""(?i)(cidr_blocks|source_ranges|cidr_ip)\s*=?\s*[:=]?\s*\[?\s*["']0\.0\.0\.0/0["']"""),
    ("MEDIUM", "WEAK_HASH", r"(?i)\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(\s*[\"'](MD5|SHA-?1)"),
    ("MEDIUM", "ECB_OR_DES", r"(?i)(AES/ECB|MODE_ECB|\bDES\b/|DESede|\bRC4\b)"),  # scan:ignore
    ("MEDIUM", "DEBUG_ENABLED", r"(?i)\b(debug)\s*[:=]\s*(true|1)\b|app\.run\(.*debug\s*=\s*True"),
    ("MEDIUM", "PERMISSIVE_CHMOD", r"chmod\s+(-R\s+)?0?777"),
]
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def scan_file(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for n, line in enumerate(lines, 1):
        if "scan:ignore" in line:
            continue
        seen = set()
        for sev, name, rx in RULES:
            if name in seen:
                continue
            if re.search(rx, line):
                seen.add(name)
                out.append({"severity": sev, "rule": name, "file": path, "line": n,
                            "snippet": line.strip()[:120]})
    return out


def walk(root, exclude=()):
    if os.path.isfile(root):
        yield root
        return
    skip = SKIP_DIRS | set(exclude)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in skip]
        for f in fn:
            if os.path.splitext(f)[1].lower() in EXTS or f.startswith(".env") or f == "Dockerfile":
                yield os.path.join(dp, f)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=LEVELS, default=None)
    ap.add_argument("--exclude", action="append", default=[], help="directory name to skip (repeatable)")
    a = ap.parse_args(argv)
    if not os.path.exists(a.path):
        sys.exit(f"error: path not found: {a.path}")
    findings = [x for f in sorted(walk(a.path, a.exclude)) for x in scan_file(f)]
    findings.sort(key=lambda x: (-LEVELS.index(x["severity"]), x["file"], x["line"]))
    if a.json:
        print(json.dumps(findings, indent=2))
    else:
        print("| Severity | Rule | Location | Snippet |\n|---|---|---|---|")
        for x in findings:
            print(f"| {x['severity']} | {x['rule']} | {x['file']}:{x['line']} | `{x['snippet']}` |")
    if a.fail_on and any(LEVELS.index(x["severity"]) >= LEVELS.index(a.fail_on) for x in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
