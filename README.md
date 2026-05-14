#!/usr/bin/env python3
"""
PrivacyShield CLI - Python companion tool
Uses: python-gnupg (GnuPG), cryptography (OpenSSL), argparse
Compatible with Kali Linux (GnuPG and OpenSSL pre-installed)
"""

import os
import sys
import json
import base64
import hashlib
import argparse
import re
import getpass
from datetime import datetime

try:
    import gnupg
except ImportError:
    print("[!] python-gnupg not found. Run: pip install python-gnupg")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH, generate_private_key, EllipticCurvePublicKey, SECP256R1
    )
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[!] cryptography not found. Run: pip install cryptography")
    sys.exit(1)


# ─────────────────────────────────────────
# COLOUR OUTPUT (works on Kali terminal)
# ─────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    PURPLE = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔═══════════════════════════════════════════════════╗
║         PrivacyShield CLI  v3                     ║
║   E2EE  +  Metadata Protection  +  GnuPG Mode    ║
╚═══════════════════════════════════════════════════╝{C.RESET}
{C.DIM}  Tools: python-gnupg | cryptography (OpenSSL)     {C.RESET}
""")

def ok(msg):    print(f"{C.GREEN}[+]{C.RESET} {msg}")
def info(msg):  print(f"{C.CYAN}[*]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def head(msg):  print(f"\n{C.PURPLE}{C.BOLD}=== {msg} ==={C.RESET}")


# ─────────────────────────────────────────
# MODE 1: GnuPG ENCRYPTION
# Using python-gnupg which wraps the GnuPG binary
# ─────────────────────────────────────────
class GPGMode:
    def __init__(self, gpg_home=None):
        home = gpg_home or os.path.expanduser("~/.privacyshield/gnupg")
        os.makedirs(home, mode=0o700, exist_ok=True)
        self.gpg = gnupg.GPG(gnupghome=home)
        self.gpg.encoding = "utf-8"
        info(f"GPG home: {home}")

    def generate_key(self, name, email, passphrase):
        head("GnuPG Key Generation")
        info(f"Generating RSA-4096 GPG key pair for {name} <{email}>")
        input_data = self.gpg.gen_key_input(
            key_type="RSA",
            key_length=4096,
            name_real=name,
            name_email=email,
            passphrase=passphrase,
            expire_date="2y",
        )
        key = self.gpg.gen_key(input_data)
        if not key:
            err("Key generation failed.")
            return None
        ok(f"Key generated — fingerprint: {key.fingerprint}")
        return key.fingerprint

    def list_keys(self, private=False):
        head("GnuPG Keys")
        keys = self.gpg.list_keys(private)
        if not keys:
            warn("No keys found.")
            return
        for k in keys:
            print(f"  {C.CYAN}Fingerprint:{C.RESET} {k['fingerprint']}")
            for uid in k["uids"]:
                print(f"  {C.DIM}UID:{C.RESET}         {uid}")
            print(f"  {C.DIM}Created:{C.RESET}     {k['date']}")
            print()

    def export_public_key(self, fingerprint, output_file=None):
        head("Export Public Key")
        pub = self.gpg.export_keys(fingerprint)
        if not pub:
            err("Key not found.")
            return None
        if output_file:
            with open(output_file, "w") as f:
                f.write(pub)
            ok(f"Public key exported to {output_file}")
        else:
            print(pub)
        return pub

    def import_key(self, key_data_or_file):
        head("Import Key")
        if os.path.isfile(key_data_or_file):
            with open(key_data_or_file, "r") as f:
                key_data = f.read()
        else:
            key_data = key_data_or_file
        result = self.gpg.import_keys(key_data)
        if result.count > 0:
            ok(f"Imported {result.count} key(s): {result.fingerprints}")
        else:
            err("No keys imported. Check the key format.")
        return result

    def encrypt_message(self, plaintext, recipient_fingerprints):
        head("GnuPG Encrypt")
        info(f"Encrypting for: {', '.join(recipient_fingerprints)}")
        encrypted = self.gpg.encrypt(
            plaintext,
            recipients=recipient_fingerprints,
            always_trust=True,
        )
        if not encrypted.ok:
            err(f"Encryption failed: {encrypted.status}")
            return None
        ok("Message encrypted with GnuPG (RSA-4096 + AES-256)")
        return str(encrypted)

    def decrypt_message(self, ciphertext, passphrase):
        head("GnuPG Decrypt")
        decrypted = self.gpg.decrypt(ciphertext, passphrase=passphrase)
        if not decrypted.ok:
            err(f"Decryption failed: {decrypted.status}")
            return None
        ok("Message decrypted successfully")
        return str(decrypted)

    def fingerprint_verify(self, fingerprint1, fingerprint2):
        head("Fingerprint Verification")
        fp1 = fingerprint1.upper().replace(" ", "")
        fp2 = fingerprint2.upper().replace(" ", "")
        groups1 = [fp1[i:i+4] for i in range(0, len(fp1), 4)]
        groups2 = [fp2[i:i+4] for i in range(0, len(fp2), 4)]
        print(f"\n  Key 1: ", end="")
        for g in groups1:
            print(f"{C.CYAN}{g}{C.RESET} ", end="")
        print(f"\n  Key 2: ", end="")
        all_match = True
        for g1, g2 in zip(groups1, groups2):
            match = g1 == g2
            if not match:
                all_match = False
            colour = C.GREEN if match else C.RED
            print(f"{colour}{g2}{C.RESET} ", end="")
        print()
        if all_match:
            ok("Fingerprints MATCH — keys are genuine")
        else:
            err("Fingerprints DO NOT MATCH — possible tampering detected")
        return all_match


# ─────────────────────────────────────────
# MODE 2: OpenSSL-BASED ECDH + AES-256-GCM
# Using the cryptography library (wraps OpenSSL)
# ─────────────────────────────────────────
class OpenSSLMode:
    KEY_DIR = os.path.expanduser("~/.privacyshield/ecdh")

    def __init__(self):
        os.makedirs(self.KEY_DIR, mode=0o700, exist_ok=True)

    def generate_keypair(self, key_name):
        head("ECDH Key Generation (OpenSSL / P-256)")
        private_key = generate_private_key(SECP256R1(), default_backend())
        pub_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        priv_path = os.path.join(self.KEY_DIR, f"{key_name}_private.pem")
        pub_path  = os.path.join(self.KEY_DIR, f"{key_name}_public.pem")

        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        os.chmod(priv_path, 0o600)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)

        fingerprint = self._key_fingerprint(pub_key)
        ok(f"Private key saved to: {priv_path}")
        ok(f"Public key saved to:  {pub_path}")
        ok(f"Key fingerprint: {fingerprint}")

        return priv_path, pub_path, fingerprint

    def _load_private_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def _load_public_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def _key_fingerprint(self, pub_key):
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(pub_bytes).hexdigest().upper()
        return " ".join([digest[i:i+4] for i in range(0, 32, 4)])

    def derive_shared_key(self, my_private_key_path, contact_public_key_path):
        head("ECDH Shared Key Derivation (OpenSSL)")
        priv_key = self._load_private_key(my_private_key_path)
        contact_pub = self._load_public_key(contact_public_key_path)

        shared_secret = priv_key.exchange(ECDH(), contact_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"privacyshield-v3",
            backend=default_backend(),
        ).derive(shared_secret)

        ok("Shared secret derived via ECDH (no secret transmitted)")
        info(f"Derived key (hex): {derived_key.hex()[:16]}... [truncated for display]")
        return derived_key

    def encrypt(self, plaintext: str, key: bytes, pad=True):
        head("AES-256-GCM Encryption (OpenSSL)")
        plain_bytes = plaintext.encode("utf-8")

        if pad:
            # ISO/IEC 7816-4 padding to 256-byte blocks
            plain_bytes += b"\x80"
            pad_len = 256 - (len(plain_bytes) % 256)
            if pad_len != 256:
                plain_bytes += b"\x00" * pad_len
            info("Message padded to hide true length (ISO/IEC 7816-4)")

        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plain_bytes, None)

        payload = {
            "version": "PS1-OPENSSL",
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "padded": pad,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        ok("Message encrypted with AES-256-GCM")
        ok(f"Nonce: {nonce.hex()}")
        ok(f"Ciphertext length: {len(ciphertext)} bytes")
        return json.dumps(payload)

    def decrypt(self, payload_json: str, key: bytes):
        head("AES-256-GCM Decryption (OpenSSL)")
        payload = json.loads(payload_json)
        if payload.get("version") != "PS1-OPENSSL":
            err("Unrecognised payload format.")
            return None

        nonce = base64.b64decode(payload["nonce_b64"])
        ciphertext = base64.b64decode(payload["ciphertext_b64"])
        padded = payload.get("padded", False)

        aesgcm = AESGCM(key)
        try:
            plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            err("Decryption failed — wrong key or corrupted ciphertext (GCM auth tag mismatch)")
            return None

        if padded:
            idx = plain_bytes.rfind(b"\x80")
            if idx != -1:
                plain_bytes = plain_bytes[:idx]

        ok("Decrypted successfully")
        if payload.get("timestamp"):
            info(f"Message was encrypted at: {payload['timestamp']}")
        return plain_bytes.decode("utf-8")

    def password_encrypt(self, plaintext: str, password: str, pad=True):
        head("Password-Based Encryption (PBKDF2-SHA256 + AES-256-GCM)")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310000,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))
        info("Key derived: PBKDF2-SHA256, 310,000 iterations (OWASP 2023)")

        plain_bytes = plaintext.encode("utf-8")
        if pad:
            plain_bytes += b"\x80"
            pl = 256 - (len(plain_bytes) % 256)
            if pl != 256:
                plain_bytes += b"\x00" * pl

        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plain_bytes, None)

        payload = {
            "version": "PS1-PASSWORD",
            "salt_b64": base64.b64encode(salt).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "padded": pad,
            "iterations": 310000,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        ok("Message encrypted with AES-256-GCM (password mode)")
        return json.dumps(payload)

    def password_decrypt(self, payload_json: str, password: str):
        head("Password-Based Decryption (PBKDF2-SHA256 + AES-256-GCM)")
        payload = json.loads(payload_json)
        if payload.get("version") != "PS1-PASSWORD":
            err("Unrecognised payload format.")
            return None

        salt = base64.b64decode(payload["salt_b64"])
        nonce = base64.b64decode(payload["nonce_b64"])
        ciphertext = base64.b64decode(payload["ciphertext_b64"])
        iterations = payload.get("iterations", 310000)
        padded = payload.get("padded", False)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))

        aesgcm = AESGCM(key)
        try:
            plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            err("Decryption failed — wrong password or corrupted ciphertext")
            return None

        if padded:
            idx = plain_bytes.rfind(b"\x80")
            if idx != -1:
                plain_bytes = plain_bytes[:idx]

        ok("Decrypted successfully")
        return plain_bytes.decode("utf-8")

    def show_fingerprint(self, public_key_path):
        head("Key Fingerprint (SHA-256)")
        pub_key = self._load_public_key(public_key_path)
        fp = self._key_fingerprint(pub_key)
        print(f"\n  {C.PURPLE}", end="")
        for group in fp.split():
            print(f"[ {group} ] ", end="")
        print(f"{C.RESET}\n")
        info("Share this fingerprint out-of-band (phone call / in person) to verify key authenticity")
        return fp


# ─────────────────────────────────────────
# MODE 3: METADATA ANALYZER
# ─────────────────────────────────────────
METADATA_PATTERNS = [
    ("Email address",       r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b",                             "HIGH"),
    ("Phone number",        r"(\+?\d[\d\s\-().]{6,}\d)",                                   "HIGH"),
    ("IP address",          r"\b(\d{1,3}\.){3}\d{1,3}\b",                                  "HIGH"),
    ("Street address",      r"\b\d+\s+[A-Z][a-z]+\s+(Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b", "HIGH"),
    ("Postcode / ZIP",      r"\b([A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}|\d{5}(-\d{4})?)\b","HIGH"),
    ("Credit card",         r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",             "HIGH"),
    ("Passport-like number",r"\b[A-Z]{1,2}\d{7,8}\b",                                      "HIGH"),
    ("Full name pattern",   r"\b([A-Z][a-z]+\s[A-Z][a-z]+)\b",                             "MED"),
    ("URL / domain",        r"https?://[^\s]+|www\.[^\s]+",                                 "MED"),
    ("Specific date",       r"\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",                       "LOW"),
]

RISK_COLOUR = {"HIGH": C.RED, "MED": C.YELLOW, "LOW": C.GREEN}

def analyze_metadata(text, auto_redact=False):
    head("Metadata Analyzer")
    findings = []
    clean = text

    for label, pattern, risk in METADATA_PATTERNS:
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        flat = [m if isinstance(m, str) else m[0] for m in matches]
        if flat:
            findings.append((label, flat, risk))

    if not findings:
        ok("No obvious PII detected — message appears clean")
        return text, []

    warn(f"Found {len(findings)} PII category/categories:")
    high = sum(1 for _, _, r in findings if r == "HIGH")
    med  = sum(1 for _, _, r in findings if r == "MED")
    low  = sum(1 for _, _, r in findings if r == "LOW")
    print(f"  {C.RED}{high} HIGH{C.RESET}  {C.YELLOW}{med} MED{C.RESET}  {C.GREEN}{low} LOW{C.RESET}\n")

    for label, matches, risk in findings:
        col = RISK_COLOUR[risk]
        print(f"  {col}[{risk}]{C.RESET} {C.BOLD}{label}{C.RESET}")
        print(f"       Detected: {', '.join(str(m) for m in matches[:3])}"
              + (f" (+{len(matches)-3} more)" if len(matches) > 3 else ""))

    if auto_redact:
        print()
        info("Auto-redacting all detected items...")
        for _, _, risk in findings:
            pass
        for label, pattern, risk in METADATA_PATTERNS:
            clean = re.sub(pattern, "[REDACTED]", clean, flags=re.IGNORECASE)
        ok("Redacted version ready")
        print(f"\n{C.DIM}--- Redacted Message ---{C.RESET}")
        print(clean)
        print(f"{C.DIM}--- End ---{C.RESET}\n")

    return clean, findings


# ─────────────────────────────────────────
# CLI ARGUMENT PARSER
# ─────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="privacyshield",
        description="PrivacyShield CLI — Privacy tool using GnuPG and OpenSSL (cryptography library)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
--------
  # GnuPG: generate key
  python3 privacyshield_cli.py gpg --generate --name "Alice" --email alice@example.com

  # GnuPG: list keys
  python3 privacyshield_cli.py gpg --list

  # GnuPG: export public key
  python3 privacyshield_cli.py gpg --export <fingerprint> --output alice_pub.asc

  # GnuPG: encrypt a message
  python3 privacyshield_cli.py gpg --encrypt --recipient <fingerprint> --input message.txt

  # OpenSSL: generate ECDH key pair
  python3 privacyshield_cli.py openssl --generate --name alice

  # OpenSSL: encrypt with ECDH shared key
  python3 privacyshield_cli.py openssl --encrypt --my-key alice_private.pem --contact-key bob_public.pem --input message.txt

  # OpenSSL: password encrypt
  python3 privacyshield_cli.py openssl --password-encrypt --input message.txt --output encrypted.json

  # Metadata: analyze a message
  python3 privacyshield_cli.py metadata --input message.txt --redact
        """
    )
    sub = p.add_subparsers(dest="mode", required=True)

    # GPG subcommand
    gpg = sub.add_parser("gpg", help="GnuPG-based encryption (RSA-4096)")
    gpg.add_argument("--generate", action="store_true", help="Generate a new GPG key pair")
    gpg.add_argument("--list",     action="store_true", help="List all stored GPG keys")
    gpg.add_argument("--export",   metavar="FINGERPRINT", help="Export public key")
    gpg.add_argument("--import-key", metavar="FILE_OR_KEY", help="Import a public key")
    gpg.add_argument("--encrypt",  action="store_true", help="Encrypt a message")
    gpg.add_argument("--decrypt",  action="store_true", help="Decrypt a message")
    gpg.add_argument("--verify-fingerprints", nargs=2, metavar=("FP1","FP2"), help="Compare two fingerprints")
    gpg.add_argument("--name",      metavar="NAME",  help="Your name (for key generation)")
    gpg.add_argument("--email",     metavar="EMAIL", help="Your email (for key generation)")
    gpg.add_argument("--recipient", metavar="FP",    help="Recipient fingerprint (for encrypt)")
    gpg.add_argument("--input",     metavar="FILE",  help="Input file or - for stdin")
    gpg.add_argument("--output",    metavar="FILE",  help="Output file")
    gpg.add_argument("--gpg-home",  metavar="DIR",   help="Custom GPG home directory")

    # OpenSSL subcommand
    ossl = sub.add_parser("openssl", help="ECDH P-256 + AES-256-GCM via OpenSSL (cryptography library)")
    ossl.add_argument("--generate",         action="store_true", help="Generate ECDH P-256 key pair")
    ossl.add_argument("--fingerprint",      metavar="FILE",      help="Show fingerprint of a public key")
    ossl.add_argument("--encrypt",          action="store_true", help="Encrypt with ECDH derived key")
    ossl.add_argument("--decrypt",          action="store_true", help="Decrypt with ECDH derived key")
    ossl.add_argument("--password-encrypt", action="store_true", help="Encrypt with password (PBKDF2)")
    ossl.add_argument("--password-decrypt", action="store_true", help="Decrypt with password (PBKDF2)")
    ossl.add_argument("--name",        metavar="NAME",  help="Key name (for generation)")
    ossl.add_argument("--my-key",      metavar="FILE",  help="Your private key PEM file")
    ossl.add_argument("--contact-key", metavar="FILE",  help="Contact's public key PEM file")
    ossl.add_argument("--input",       metavar="FILE",  help="Input file or - for stdin")
    ossl.add_argument("--output",      metavar="FILE",  help="Output file")
    ossl.add_argument("--no-pad",      action="store_true", help="Disable message padding")

    # Metadata subcommand
    meta = sub.add_parser("metadata", help="Analyze text for PII / metadata risks")
    meta.add_argument("--input",  metavar="FILE", help="Input file or - for stdin")
    meta.add_argument("--redact", action="store_true", help="Auto-redact detected PII")
    meta.add_argument("--output", metavar="FILE", help="Write redacted version to file")

    return p


def read_input(source):
    if source is None:
        return input("Enter message: ")
    if source == "-":
        return sys.stdin.read().strip()
    with open(source, "r") as f:
        return f.read().strip()

def write_output(data, dest):
    if dest:
        with open(dest, "w") as f:
            f.write(data)
        ok(f"Output written to {dest}")
    else:
        print(f"\n{C.DIM}--- Output ---{C.RESET}")
        print(data)
        print(f"{C.DIM}--- End ---{C.RESET}\n")


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    # ──── GPG MODE ────
    if args.mode == "gpg":
        gpg = GPGMode(gpg_home=getattr(args, "gpg_home", None))

        if args.generate:
            name = args.name or input("Your name: ")
            email = args.email or input("Your email: ")
            passphrase = getpass.getpass("Passphrase for your key: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                err("Passphrases do not match.")
                sys.exit(1)
            gpg.generate_key(name, email, passphrase)

        elif args.list:
            gpg.list_keys(private=False)
            gpg.list_keys(private=True)

        elif args.export:
            gpg.export_public_key(args.export, output_file=getattr(args, "output", None))

        elif getattr(args, "import_key", None):
            gpg.import_key(args.import_key)

        elif args.encrypt:
            if not args.recipient:
                err("--recipient fingerprint is required for encryption.")
                sys.exit(1)
            text = read_input(getattr(args, "input", None))
            _, pii = analyze_metadata(text)
            if pii:
                warn("PII detected in message. Consider redacting before encrypting.")
                proceed = input("Proceed anyway? [y/N]: ")
                if proceed.lower() != "y":
                    info("Encryption cancelled.")
                    sys.exit(0)
            result = gpg.encrypt_message(text, [args.recipient])
            if result:
                write_output(result, getattr(args, "output", None))

        elif args.decrypt:
            text = read_input(getattr(args, "input", None))
            passphrase = getpass.getpass("Passphrase: ")
            result = gpg.decrypt_message(text, passphrase)
            if result:
                write_output(result, getattr(args, "output", None))

        elif getattr(args, "verify_fingerprints", None):
            fp1, fp2 = args.verify_fingerprints
            gpg.fingerprint_verify(fp1, fp2)

    # ──── OPENSSL MODE ────
    elif args.mode == "openssl":
        ossl = OpenSSLMode()

        if args.generate:
            name = args.name or input("Key name (e.g. alice): ")
            ossl.generate_keypair(name)

        elif getattr(args, "fingerprint", None):
            ossl.show_fingerprint(args.fingerprint)

        elif args.encrypt:
            if not args.my_key or not args.contact_key:
                err("--my-key and --contact-key are both required.")
                sys.exit(1)
            key = ossl.derive_shared_key(args.my_key, args.contact_key)
            text = read_input(getattr(args, "input", None))
            _, pii = analyze_metadata(text)
            if pii:
                warn("PII detected. Consider redacting.")
                proceed = input("Proceed anyway? [y/N]: ")
                if proceed.lower() != "y":
                    sys.exit(0)
            pad = not getattr(args, "no_pad", False)
            result = ossl.encrypt(text, key, pad=pad)
            write_output(result, getattr(args, "output", None))

        elif args.decrypt:
            if not args.my_key or not args.contact_key:
                err("--my-key and --contact-key are both required.")
                sys.exit(1)
            key = ossl.derive_shared_key(args.my_key, args.contact_key)
            text = read_input(getattr(args, "input", None))
            result = ossl.decrypt(text, key)
            if result:
                write_output(result, getattr(args, "output", None))

        elif getattr(args, "password_encrypt", False):
            text = read_input(getattr(args, "input", None))
            pw = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm: ")
            if pw != confirm:
                err("Passwords do not match.")
                sys.exit(1)
            pad = not getattr(args, "no_pad", False)
            result = ossl.password_encrypt(text, pw, pad=pad)
            write_output(result, getattr(args, "output", None))

        elif getattr(args, "password_decrypt", False):
            text = read_input(getattr(args, "input", None))
            pw = getpass.getpass("Password: ")
            result = ossl.password_decrypt(text, pw)
            if result:
                write_output(result, getattr(args, "output", None))

    # ──── METADATA MODE ────
    elif args.mode == "metadata":
        text = read_input(getattr(args, "input", None))
        redact = getattr(args, "redact", False)
        clean, findings = analyze_metadata(text, auto_redact=redact)
        if redact and findings:
            write_output(clean, getattr(args, "output", None))


if __name__ == "__main__":
    main()
