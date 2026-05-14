# PrivacyShield v3 — Python Dependencies
# Install on Kali Linux: pip3 install -r requirements.txt --break-system-packages

# OpenSSL bindings — cryptographic backend for all encryption/key operations
# Provides: ECDH, AES-256-GCM, PBKDF2-HMAC-SHA256, HKDF, SHA-256
cryptography>=41.0.0

# GnuPG wrapper — key management, asymmetric encryption, signing, verification
python-gnupg>=0.5.2

# Standard library only beyond this point (no additional installs needed)
# Used: os, sys, re, json, base64, argparse, getpass, csv, statistics, dataclasses
