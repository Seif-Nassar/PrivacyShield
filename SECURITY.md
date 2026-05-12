# Security Policy

## Overview

PrivacyShield is an academic project built for a university Security and Privacy module. It implements real cryptographic primitives via the browser's Web Cryptography API and is intended to demonstrate that strong privacy tooling can be made accessible to non-expert users.

This document describes the security model, known limitations, and responsible disclosure process.

---

## Supported Versions

| Version | Status |
|---------|--------|
| v2.0 (current) | Actively maintained |
| v1.0 | No longer supported |

---

## Cryptographic Assumptions

PrivacyShield's security rests on the following computational hardness assumptions.

**ECDH P-256:** The security of the key exchange relies on the elliptic curve discrete logarithm problem over the P-256 curve being computationally infeasible. This is a well-studied assumption and is the basis for key agreement in TLS 1.3, Signal, and the majority of modern secure communication systems.

**AES-256-GCM:** Confidentiality relies on the assumption that AES is a pseudorandom permutation. Authenticated integrity relies on the security of GHASH under the GCM construction. Both are widely accepted by the cryptographic community and are recommended by NIST.

**PBKDF2-SHA-256:** The password mode relies on the pre-image resistance of SHA-256 and the difficulty of inverting the PBKDF2 construction with 310,000 iterations. Resistance to brute-force attacks is bounded by password quality.

---

## Known Limitations

The following limitations are intentional design trade-offs or out-of-scope concerns for this version. They are not vulnerabilities.

**Channel metadata exposure**
PrivacyShield encrypts message content. It does not hide the fact that you are using the tool, your IP address, the timing of your communications, or the approximate size of encrypted messages (partially mitigated by optional padding). Users who need to protect channel metadata should use Tor or a comparable anonymising network.

**Endpoint security**
PrivacyShield operates on plaintext before encryption and after decryption. If the device running the tool is compromised by malware, keyloggers, or a malicious browser extension, plaintext messages may be captured at those points. Cryptographic tools cannot protect against endpoint compromise.

**Quantum computing**
AES-256 is considered post-quantum resistant under current analysis, providing approximately 128-bit security against Grover's algorithm. ECDH over P-256 is not considered quantum-resistant. A future version will migrate the key exchange to a post-quantum algorithm such as CRYSTALS-Kyber (NIST PQC Round 4 finalist) once browser support is available.

**Regex-based metadata detection**
The metadata analyzer detects personally identifying information using regular expression patterns. It will not detect all possible identifiers, particularly free-form personal references, nicknames, contextual location descriptions, or code words that are meaningful only to the parties involved. Users should treat the analyzer as a risk-reduction tool rather than a comprehensive sanitisation guarantee.

**Key persistence**
Private keys and shared secrets exist only in memory for the duration of the browser session. They are not stored anywhere. This means losing the session loses the keys, and there is no recovery mechanism. Users are responsible for exporting and securely storing their private keys if they need them beyond a single session.

**No certificate or identity binding**
The tool does not implement any form of identity verification. A public key presented by a contact cannot be verified as belonging to the claimed person. Users must verify public keys through a trusted out-of-band channel to prevent person-in-the-middle attacks.

---

## Reporting a Vulnerability

If you discover a security issue in PrivacyShield, please report it responsibly.

**What to report:**
- Cryptographic weaknesses or implementation errors in the key exchange, encryption, or key derivation code
- Bugs that allow recovery of plaintext, private keys, or shared secrets
- Metadata analyzer bypasses that allow high-risk PII to pass undetected

**How to report:**
Open a GitHub issue tagged `[SECURITY]`. For sensitive findings that should not be disclosed publicly before a fix is available, include only a brief description in the issue and request a private communication channel.

**What not to report:**
The limitations listed in the section above are known and intentional. Please do not file issues for channel metadata exposure, quantum resistance, or endpoint security, as these are acknowledged design constraints.

---

## Responsible Use

PrivacyShield is a privacy tool, not an anonymity tool. It protects message content and reduces PII exposure in text. It does not make users anonymous, hide network-level behaviour, or provide protection against a fully compromised device or operating system.

Users who require anonymity in addition to encryption should use PrivacyShield in combination with Tor Browser or a comparable anonymising network.
