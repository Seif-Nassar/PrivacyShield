# PrivacyShield v3

**End-to-end encryption and metadata protection for non-expert users.**

Security and Privacy Module | Project 13: Usable Privacy — Cryptographic Tooling for Non-Expert Users

---

## Tools Used

| Tool | Role in Project |
|------|----------------|
| **Python 3** | Backend CLI, cryptographic operations, metadata analysis, UX research toolkit |
| **OpenSSL** (`cryptography` library) | ECDH key exchange, AES-256-GCM encryption, PBKDF2 key derivation, SHA-256 fingerprints |
| **GnuPG** (`python-gnupg`) | Alternative asymmetric encryption path, key signing, signature verification |
| **Kali Linux** | Development and testing environment — see `docs/kali_setup.md` |
| **UX Research Methodologies** | Think-aloud protocol, System Usability Scale (SUS), task-based evaluation — see `src/ux_research.py` and `docs/usability_study.md` |

---

## Project Structure

```
privacyshield/
│
├── index.html                  Browser-based frontend (Web Crypto API)
│
├── src/
│   ├── privacyshield.py        Python CLI — ECDH, AES-256-GCM, GnuPG integration
│   ├── metadata_analyzer.py    Python PII scanner — 14 detection patterns
│   ├── ux_research.py          SUS calculator, think-aloud logger, study analyser
│   └── requirements.txt        Python dependencies (cryptography, python-gnupg)
│
├── docs/
│   ├── kali_setup.md           Kali Linux setup + raw OpenSSL and GPG commands
│   ├── architecture.md         Detailed cryptographic architecture
│   ├── research_paper.md       Full academic paper
│   └── usability_study.md      Moderated think-aloud study report (n=12)
│
├── SECURITY.md                 Security model and responsible disclosure
├── LICENSE                     MIT License
└── README.md                   This file
```

---

## Features

### True End-to-End Encryption (ECDH P-256 + AES-256-GCM)

Each user generates an asymmetric key pair using ECDH over the P-256 curve (OpenSSL backend). Both parties independently derive the same shared secret — nothing secret is ever transmitted. Messages are encrypted with AES-256-GCM providing both confidentiality and authenticated integrity.

### Metadata Analyzer (14 PII Categories)

Scans message text before encryption for personally identifying information. Detects email addresses, phone numbers, IP addresses, street addresses, postcodes, credit card patterns, passport numbers, national ID patterns, full name patterns, URLs, dates of birth, calendar dates, vehicle registrations, and SSN patterns. Provides colour-coded risk reports with plain-English advice and one-click redaction.

### Key Fingerprint Verification

SHA-256 fingerprints of public keys displayed as colour-coded hex groups for out-of-band identity verification. Prevents person-in-the-middle attacks by letting users compare fingerprints by phone call or in person.

### GnuPG Integration

Full GPG key management via the Python CLI: generate, export, import, encrypt, decrypt, sign, and verify. Provides an alternative encryption path and supports non-repudiation through digital signatures.

### Secure Encrypted Notes

In-session notepad encrypted with AES-256-GCM using the derived ECDH shared key. Zero persistence — no localStorage, no cookies, no server. Closing the tab is a cryptographic wipe.

### Session Audit Log

Every cryptographic operation (key generation, encryption, decryption, metadata scan, note save) logged with timestamps in the browser session for full transparency.

### UX Research Toolkit

Python module implementing the evaluation methodology: SUS questionnaire scoring (Brooke, 1996), think-aloud session logger, task timing and success rate calculator, and CSV export for statistical analysis.

---

## Cryptographic Specification

```
Key Exchange:   ECDH P-256 (secp256r1) via OpenSSL
Cipher:         AES-256-GCM (authenticated encryption)
KDF (pwd mode): PBKDF2-HMAC-SHA256, 310,000 iterations, 128-bit random salt
KDF (E2EE):     HKDF-SHA256 applied to ECDH output material
IV:             96-bit cryptographically random nonce per message
Padding:        ISO/IEC 7816-4 (256-byte blocks, enabled by default)
Fingerprint:    SHA-256 over DER-encoded SubjectPublicKeyInfo
GPG keys:       RSA-4096 via GnuPG
```

---

## Quick Start on Kali Linux

```bash
# Install dependencies
cd privacyshield/src
pip3 install -r requirements.txt --break-system-packages

# Generate key pair
python3 privacyshield.py keygen --output ./my_keys

# Scan message for metadata risks
python3 metadata_analyzer.py -t "Call me on 07700900123" --redact

# Encrypt a message (E2EE mode)
python3 privacyshield.py encrypt \
    --mode e2ee \
    --my-privkey ./my_keys/private_key.pem \
    --their-pubkey ./contact_pub.pem \
    --message "The meeting is on Thursday" \
    --output-file message.enc

# Decrypt
python3 privacyshield.py decrypt \
    --file message.enc \
    --my-privkey ./my_keys/private_key.pem \
    --their-pubkey ./sender_pub.pem

# Run SUS questionnaire (UX study)
python3 ux_research.py sus --participant P01 --data-dir ./study_data
```

Full Kali Linux setup with raw OpenSSL and GPG commands: see `docs/kali_setup.md`

---

## Browser Frontend

Open `index.html` in any modern browser. No installation required. Uses the W3C Web Crypto API (browser-native OpenSSL-equivalent). All operations run 100% locally — nothing is sent to any server.

---

## Usability Study Results

Evaluated using the **System Usability Scale** and **think-aloud protocol** with n = 12 non-expert participants on Kali Linux (CLI) and browser (frontend):

| Metric | Result |
|--------|--------|
| Overall task success rate | 91.7% |
| SUS score | 81.4 / 100 (Good) |
| Metadata analyzer success rate | 100% |
| Participants who would use daily | 9 / 12 |

---

## License

MIT License. See `LICENSE`.
