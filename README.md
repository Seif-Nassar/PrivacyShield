# PrivacyShield

**End-to-end encryption and metadata protection for non-expert users.**

PrivacyShield is a zero-dependency, browser-native cryptographic privacy tool that combines genuine end-to-end encryption via Elliptic Curve Diffie-Hellman key exchange with a real-time metadata analyzer. It was built on the principle that strong privacy should be accessible to everyone, not only those with a background in information security.

The entire application ships as a single HTML file. No installation. No server. No accounts. No telemetry of any kind.

---

## Live Demo

Open `index.html` in any modern browser. No build step required.

---

## Features

### End-to-End Encryption (ECDH + AES-256-GCM)

PrivacyShield implements the same key exchange model used by Signal and TLS 1.3. Each user generates an asymmetric key pair using ECDH over the P-256 curve. Public keys are exchanged openly. Both parties independently derive an identical shared secret from their own private key and the other party's public key. That shared secret is never transmitted, which means there is no point of interception.

Messages are then encrypted using AES-256-GCM, a mode of AES that provides both confidentiality and authenticated integrity. If a ciphertext is modified in transit, decryption fails cleanly before any corrupted content is shown.

### Metadata Analyzer

Encryption protects what a message says. The metadata analyzer protects who wrote it. Before any message is encrypted, the analyzer scans the plaintext for personally identifying information across eight detection categories and presents findings with colour-coded risk indicators, plain-English explanations, and a one-click auto-redact option.

**Detected categories:**

| Category | Risk Level |
|----------|------------|
| Email addresses | High |
| Phone numbers | High |
| IP addresses | High |
| Street addresses | High |
| Postcodes and ZIP codes | High |
| Full name patterns | Medium |
| URLs and domains | Medium |
| Specific dates | Low |

### Message Length Padding

Even encrypted messages leak information through their length. PrivacyShield optionally pads messages to the nearest 256-byte boundary following the ISO/IEC 7816-4 standard, making length-based traffic analysis significantly less effective. Padding is enabled by default.

### Password Fallback Mode

For situations where a full key exchange is not practical, a password-based encryption mode is available. Passwords are converted to cryptographic keys using PBKDF2-SHA-256 with 310,000 iterations and a 128-bit random salt, following OWASP 2023 recommendations for password hashing.

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Key Exchange | ECDH P-256 (Web Crypto API) | Asymmetric key pair generation and shared secret derivation |
| Symmetric Encryption | AES-256-GCM (Web Crypto API) | Authenticated encryption of message content |
| Key Derivation | PBKDF2-SHA-256 (Web Crypto API) | Deriving encryption keys from user passwords |
| Randomness | `crypto.getRandomValues` (Web Crypto API) | Cryptographically secure IV, salt, and nonce generation |
| Encoding | Base64 (built-in browser API) | Encoding binary ciphertext for text-based transmission |
| Padding | ISO/IEC 7816-4 | Message length normalisation to resist traffic analysis |
| Metadata Detection | Vanilla JavaScript (RegExp) | Pattern-based PII detection across eight categories |
| Interface | HTML5, CSS3, Vanilla JavaScript (ES2020) | Single-file browser application, no framework |
| Typography | Google Fonts CDN (DM Mono, Syne, DM Sans) | Interface typography |

**Zero third-party cryptographic dependencies.** All cryptographic primitives are provided by the browser's built-in Web Cryptography API (W3C Recommendation, 2017), eliminating supply-chain risk from external libraries.

---

## Cryptographic Specification

### Key Exchange

```
Algorithm:    ECDH (Elliptic Curve Diffie-Hellman)
Curve:        P-256 (secp256r1, NIST recommended)
Key format:   JWK (JSON Web Key), Base64-encoded for sharing
Extractable:  Public key: yes / Private key: no (browser enforced)
```

### Symmetric Encryption

```
Algorithm:    AES-GCM (Galois/Counter Mode)
Key length:   256 bits
IV length:    96 bits (12 bytes), cryptographically random per message
Auth tag:     128 bits (GCM default)
Output:       PS1E:<base64(iv[12] + ciphertext + tag)>  (E2EE mode)
              PS1P:<base64(pad_flag[1] + salt[16] + iv[12] + ciphertext + tag)>  (password mode)
```

### Key Derivation (Password Mode)

```
Algorithm:    PBKDF2
Hash:         SHA-256
Iterations:   310,000  (OWASP 2023 recommendation)
Salt:         128 bits (16 bytes), cryptographically random per message
Output:       256-bit AES key
```

### Message Padding

```
Standard:     ISO/IEC 7816-4
Block size:   256 bytes
Marker byte:  0x80 appended after plaintext
Fill:         Zero bytes to next 256-byte boundary
Direction:    Applied before encryption, stripped after decryption
```

---

## Output Format Reference

```
E2EE encrypted message:
PS1E: <base64>
       └── pad_flag (1 byte) | IV (12 bytes) | ciphertext + GCM tag

Password encrypted message:
PS1P: <base64>
       └── pad_flag (1 byte) | PBKDF2 salt (16 bytes) | IV (12 bytes) | ciphertext + GCM tag
```

The `PS1E:` and `PS1P:` prefixes allow the decryption interface to automatically detect the encryption mode and prompt accordingly, preventing user errors from mismatched decryption attempts.

---

## Browser Compatibility

| Browser | Minimum Version | Web Crypto API Support |
|---------|----------------|------------------------|
| Chrome | 37+ | Full |
| Firefox | 34+ | Full |
| Safari | 11+ | Full |
| Edge | 12+ | Full |
| Opera | 24+ | Full |

All target browsers implement the Web Cryptography API natively with hardware-accelerated AES-NI instructions where available. No polyfills are required.

---

## Project Structure

```
privacyshield/
│
├── index.html              Main application (single-file, self-contained)
│
├── docs/
│   ├── research_paper.md   Full academic paper with cryptographic analysis
│   ├── usability_study.md  Moderated think-aloud study report (n=12)
│   └── architecture.md     Detailed technical architecture notes
│
├── SECURITY.md             Responsible disclosure policy and known limitations
├── LICENSE                 MIT License
└── README.md               This file
```

---

## Security Model

### What PrivacyShield protects against

- Passive interception of message content by network observers
- Server-side data breaches (no data is ever sent to a server)
- Ciphertext tampering (GCM authentication tag detects modifications)
- Brute-force attacks on passwords (310,000 PBKDF2 iterations)
- Message length analysis (ISO/IEC 7816-4 padding)
- PII leakage through unencrypted identifiers in message content

### What PrivacyShield does not protect against

- Channel metadata: IP addresses, connection timing, and message frequency remain visible to network observers. Use Tor or a trusted VPN for higher-threat scenarios.
- Endpoint compromise: If the device running PrivacyShield is compromised, plaintext messages are accessible before encryption and after decryption.
- Social engineering: No cryptographic tool can protect against a recipient who voluntarily forwards a decrypted message.
- Quantum adversaries: AES-256 provides 128-bit post-quantum security under Grover's algorithm. P-256 is not considered quantum-resistant. A future version will migrate to a post-quantum key exchange algorithm.
- Metadata patterns not covered by the analyzer: The current regex-based detection covers eight common PII categories but will not catch all possible identifiers.

Full details are in `SECURITY.md`.

---

## Academic Context

This project was developed for a Security and Privacy module (Project 13: Usable Privacy). The academic deliverables are included in the `docs/` folder:

- `docs/research_paper.md` covers the design rationale, cryptographic architecture, evaluation results, and six original design heuristics for usable privacy tools.
- `docs/usability_study.md` documents the full methodology, participant breakdown, task scenarios, SUS questionnaire, and findings from a twelve-participant think-aloud study.

**Key evaluation results:**
- System Usability Scale score: 81.4 / 100 (rated Good)
- Overall task success rate: 91.7%
- Metadata analyzer task success rate: 100%

---

## License

MIT License. See `LICENSE` for full terms.

---

## Contributing

Contributions are welcome. Please read `SECURITY.md` before submitting issues or pull requests related to cryptographic behaviour. For general interface improvements, open an issue describing the proposed change before submitting a pull request.

---

## Acknowledgements

Cryptographic primitives provided by the W3C Web Cryptography API. Typography by Google Fonts. Padding scheme from ISO/IEC 7816-4. PBKDF2 iteration count based on OWASP Password Storage Cheat Sheet (2023). Key exchange curve selection follows NIST SP 800-186.
