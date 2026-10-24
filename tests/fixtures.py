"""Fixture builders. Secret-looking strings are assembled at runtime so the repo
itself never contains token-shaped literals (avoids secret-scanning alerts)."""
import csv, datetime as dt, json, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc


def _name(cn, org="Test"):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pub, signer, days=365, start_offset=-1, hash_alg=None, ca=False):
    now = dt.datetime.now(UTC)
    nb = now + dt.timedelta(days=start_offset)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(nb + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(signer, hash_alg or hashes.SHA256())


def write_pem(path, *certs):
    with open(path, "wb") as f:
        for c in certs:
            f.write(c.public_bytes(serialization.Encoding.PEM))


def make_certs(d):
    os.makedirs(d, exist_ok=True)
    bad_key = ec.generate_private_key(ec.SECP256R1())
    bad_ca = _cert(_name("Bad Test Root"), _name("Bad Test Root"), bad_key.public_key(), bad_key, 3650, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_bad = _cert(_name("shop.example.com"), bad_ca.subject, leaf_key.public_key(), bad_key)
    good_key = ec.generate_private_key(ec.SECP256R1())
    good_ca = _cert(_name("Good Test Root"), _name("Good Test Root"), good_key.public_key(), good_key, 3650, ca=True)
    leaf_good = _cert(_name("www.example.com"), good_ca.subject, leaf_key.public_key(), good_key)
    expired = _cert(_name("old.example.com"), good_ca.subject, leaf_key.public_key(), good_key,
                    days=30, start_offset=-400)
    soon = _cert(_name("soon.example.com"), good_ca.subject, leaf_key.public_key(), good_key,
                 days=10, start_offset=-1)
    weak = rsa.generate_private_key(65537, 1024)
    weak_rsa = _cert(_name("weak.example.com"), good_ca.subject, weak.public_key(), good_key)
    write_pem(f"{d}/leaf_bad.pem", leaf_bad, bad_ca)       # chain under the bad CA
    write_pem(f"{d}/leaf_good.pem", leaf_good)
    write_pem(f"{d}/expired.pem", expired)
    write_pem(f"{d}/soon.pem", soon)
    write_pem(f"{d}/weak_rsa.pem", weak_rsa)
    _sha1_cert(f"{d}/sha1.pem")
    return bad_ca


def _sha1_cert(path):
    """cryptography refuses SHA-1 signing; use the openssl CLI to build a SHA-1 signed cert."""
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as t:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{t}/k.pem",
                        "-out", path, "-subj", "/CN=sha1.example.com", "-sha1", "-days", "365"],
                       check=True, capture_output=True)


def make_triage_csv(path):
    rows = [
        ["cve", "asset", "product", "exploited", "internet_exposed", "severity", "patch_available", "edge_device"],
        ["CVE-A", "gw-1", "VPN Gateway", "yes", "yes", "critical", "yes", "yes"],
        ["CVE-B", "web-1", "PHP", "yes", "yes", "critical", "no", "no"],
        ["CVE-C", "db-1", "Database", "no", "no", "high", "yes", "no"],
        ["CVE-D", "fw-1", "Firewall", "no", "yes", "high", "yes", "yes"],
        ["CVE-E", "app-1", "Library", "no", "no", "low", "yes", "no"],
        ["CVE-F", "app-2", "Runtime", "yes", "no", "high", "yes", "no"],
        ["CVE-G", "lb-1", "Load Balancer", "no", "no", "medium", "yes", "yes"],
        ["CVE-H", "web-2", "CMS", "no", "yes", "critical", "yes", "no"],
    ]
    with open(path, "w", newline="") as f:
        csv.writer(f).writerows(rows)


def make_apps_json(path):
    apps = [
        {"name": "MSP Remote Tool", "publisher_verified": False, "owner": None, "consent_type": "admin",
         "multi_tenant": True, "permissions": ["Directory.ReadWrite.All", "Mail.ReadWrite"],
         "credentials": [{"type": "secret", "created": "2026-10-10", "expires": "2028-10-10"}],
         "last_sign_in": "2026-10-20"},
        {"name": "HR Portal", "publisher_verified": True, "owner": "hr@corp.example", "consent_type": "user",
         "multi_tenant": False, "permissions": ["User.Read"],
         "credentials": [{"type": "cert", "created": "2026-01-01", "expires": "2027-01-01"}],
         "last_sign_in": "2026-10-22"},
        {"name": "Old Sync", "publisher_verified": True, "owner": "it@corp.example", "consent_type": "user",
         "multi_tenant": False, "permissions": ["Files.Read"],
         "credentials": [{"type": "secret", "created": "2024-01-01", "expires": "2025-01-01"}],
         "last_sign_in": "2025-12-01"},
    ]
    with open(path, "w") as f:
        json.dump(apps, f)


def make_code_tree(root, vulnerable=True):
    os.makedirs(root, exist_ok=True)
    if vulnerable:
        akia = "AKIA" + "IOSFODNN7EXAMPLE"
        ghp = "gh" + "p_" + "a" * 36
        pk = "-----BEGIN " + "RSA PRIVATE KEY-----"
        files = {
            "app.py": (f'import random, hashlib, requests\n'
                       f'API_KEY = "{akia}"\n'
                       f'session_token = random.randint(0, 999999)\n'
                       f'h = hashlib.md5(b"x")\n'
                       f'requests.get(url, verify=False)\n'
                       f'app.run(debug=True)\n'),
            "main.tf": 'resource "aws_security_group_rule" "r" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
            "deploy.sh": f'chmod 777 /var/www\nexport GH="{ghp}"\n',
            "key.txt": f"{pk}\nMIIE\n",
            "web.js": 'const token = Math.random().toString(36);\n',
        }
    else:
        files = {
            "app.py": ('import secrets, os, hashlib\n'
                       'API_KEY = os.environ["API_KEY"]\n'
                       'session_token = secrets.token_hex(32)\n'
                       'h = hashlib.sha256(b"x")\n'
                       'requests.get(url, timeout=5)\n'),
            "main.tf": 'resource "aws_security_group_rule" "r" {\n  cidr_blocks = ["10.0.0.0/8"]\n}\n',
            "notes.txt": "The word password appears here with no value.\n",
        }
    for name, body in files.items():
        with open(os.path.join(root, name), "w") as f:
            f.write(body)
