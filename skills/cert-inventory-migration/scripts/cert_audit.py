#!/usr/bin/env python3
"""Audit PEM certificate files for distrusted issuers and weak properties.

Usage: cert_audit.py PATH [PATH...] [--distrust PATTERN ...] [--spki-hash HEX ...] [--json]
PATH may be a PEM file (may hold a chain) or a directory of .pem/.crt files.
Flags: DISTRUSTED_ISSUER, DISTRUSTED_IN_CHAIN, DISTRUSTED_SPKI, EXPIRED,
EXPIRES_SOON (<30d), WEAK_RSA (<2048), WEAK_SIGNATURE (md5/sha1).
Exit code 1 if any certificate is flagged DISTRUSTED_*, else 0.
"""
import argparse, glob, hashlib, json, os, sys
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PEM_END = b"-----END CERTIFICATE-----"


def spki_sha256(cert):
    der = cert.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def load_file(path):
    with open(path, "rb") as fh:
        data = fh.read()
    certs = []
    for chunk in data.split(PEM_END):
        if b"BEGIN CERTIFICATE" in chunk:
            certs.append(x509.load_pem_x509_certificate(chunk[chunk.index(b"-----BEGIN"):] + PEM_END))
    return certs


def gather(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for ext in ("*.pem", "*.crt", "*.cer"):
                files += glob.glob(os.path.join(p, "**", ext), recursive=True)
        else:
            files.append(p)
    return sorted(set(files))


def audit(files, patterns, spki_hashes, now=None):
    now = now or datetime.now(timezone.utc)
    patterns = [p.lower() for p in patterns]
    spki_hashes = {h.lower() for h in spki_hashes}
    results = []
    for f in files:
        certs = load_file(f)
        names = [(c.subject.rfc4514_string() + " " + c.issuer.rfc4514_string()).lower() for c in certs]
        for i, c in enumerate(certs):
            flags = []
            issuer = c.issuer.rfc4514_string()
            sh = spki_sha256(c)
            if any(p in issuer.lower() for p in patterns):
                flags.append("DISTRUSTED_ISSUER")
            elif any(p in n for n in names for p in patterns):
                flags.append("DISTRUSTED_IN_CHAIN")
            if sh in spki_hashes:
                flags.append("DISTRUSTED_SPKI")
            end = c.not_valid_after_utc
            if end < now:
                flags.append("EXPIRED")
            elif (end - now).days < 30:
                flags.append("EXPIRES_SOON")
            key = c.public_key()
            if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
                flags.append("WEAK_RSA")
            sig = c.signature_hash_algorithm
            if sig is not None and isinstance(sig, (hashes.MD5, hashes.SHA1)):
                flags.append("WEAK_SIGNATURE")
            results.append({"file": f, "index": i, "subject": c.subject.rfc4514_string(),
                            "issuer": issuer, "not_after": end.isoformat(),
                            "spki_sha256": sh, "flags": flags})
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--distrust", action="append", default=[], help="issuer/subject substring (repeatable)")
    ap.add_argument("--spki-hash", action="append", default=[], help="SHA-256 hex of SPKI (repeatable)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    files = gather(a.paths)
    if not files:
        sys.exit("error: no certificate files found")
    res = audit(files, a.distrust, a.spki_hash)
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            print(f"{r['file']}[{r['index']}] subject={r['subject']} issuer={r['issuer']} "
                  f"expires={r['not_after'][:10]} flags={','.join(r['flags']) or '-'}")
    return 1 if any(f.startswith("DISTRUSTED") for r in res for f in r["flags"]) else 0


if __name__ == "__main__":
    sys.exit(main())
