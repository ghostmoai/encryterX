# EncryptorX

[![PyPI version](https://img.shields.io/pypi/v/encryptorx.svg)](https://pypi.org/project/encryptorx/)
[![Python versions](https://img.shields.io/pypi/pyversions/encryptorx.svg)](https://pypi.org/project/encryptorx/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A zero-dependency, audited cryptographic and steganographic suite implemented in pure Python and high-performance native Rust.

---

## Architectural Highlights

EncryptorX v3.3.0 modernizes the core encryption engine with standardized cryptographic primitives, misuse-resistant nonce generation, and clean architectural decoupling between cryptographic confidentiality and transport steganography.

### 1. RFC 8439 ChaCha20-Poly1305 AEAD Engine
- **Standardized Authenticated Encryption**: Replaces ad-hoc stream constructions with RFC 8439 ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
- **128-bit Poly1305 Authentication Tag**: Authenticates both the ciphertext and associated data (including key packaging and version headers), preventing bit-flipping, padding manipulation, and ciphertext truncation attacks.
- **SIV-Style Synthetic Nonce Derivation**: Derives a 96-bit (12-byte) initialization vector using:
  $$N = \text{HMAC-SHA256}(K, \text{CSPRNG}_{16} \parallel \text{Plaintext})[:12]$$
  This deterministic synthetic construction provides robust misuse resistance against catastrophic Two-Time Pad nonce reuse even in environments with low entropy or faulty random number generators.

### 2. Transport Encoding vs. Cryptographic Confidentiality
- **Clean Decoupling**: The 64-wrapper symbolic and numeric obfuscation layer with randomized noise injection is explicitly classified as **textual steganography and transport encoding** (designed for anti-scraping, anti-grep, and safe transport across text channels).
- **Cryptographic Guarantees**: Cryptographic secrecy, integrity, and authenticity are provided strictly by the underlying ChaCha20-Poly1305 AEAD engine and key derivation functions, adhering to Kerckhoffs's principle.

### 3. Fault-Tolerant Lossy Decryption
- **Adaptive Recovery**: When `strict=False` (default for interactive operations), the engine recovers and displays intelligible plaintext even if the transport token experiences transmission noise, character loss, or byte drops.
- **Strict Verification**: When `strict=True`, any authentication tag discrepancy, tampering, or invalid password immediately raises a `ValueError`.

### 4. 100% Backward Compatibility
- **Legacy Token Interoperability**: Decrypts legacy v2 tokens generated with SHA-256 counter stream ciphers across all legacy protection flags: `FLAG_DIRECT (0x00)`, `FLAG_PBKDF2 (0x01)`, `FLAG_SCRYPT (0x02)`, `FLAG_DOUBLE_DIRECT (0x10)`, and `FLAG_DOUBLE_CASCADE (0x12)`.
- **Legacy File Format**: Supports both format v3 (`ENCX\x03` with ChaCha20-Poly1305) and legacy format v2 (`ENCX\x02` with HMAC-SHA256).

### 5. Multi-Layer Cryptographic Suite
- **Symmetric Ciphers**: RFC 8439 ChaCha20-Poly1305 AEAD, AES-256-CTR, and AES-256-GCM AEAD.
- **Asymmetric Primitives**: RFC 7748 X25519 Elliptic Curve Diffie-Hellman (ECDH) and RFC 8032 Ed25519 Edwards-curve Digital Signatures.
- **Threshold Secret Sharing**: Shamir's Secret Sharing Scheme $(k, n)$ over $\text{GF}(256)$ with polynomial interpolation.
- **Encrypted Container Vaults**: Multi-file `.vault` archives featuring Multi-Factor Authentication (Password + 256-bit Keyfile) and adaptive compression.
- **Entropy Auditor**: NIST SP 800-22 and FIPS 140-2 statistical randomness test suite (Monobit, Poker, Long Run) and Shannon entropy calculation.
- **Carrier-Invariant Image Steganography**: LSB steganography with Hull-Dobell cycle-walking pseudo-random pixel permutation and PSNR / MSE validation metrics.

---

## Installation

### Standard Installation
```bash
pip install encryptorx
```

### Full Installation (NumPy & Pillow Acceleration)
```bash
pip install encryptorx[full]
```

### Compiling Native Rust Engine
```bash
cargo build --release
```

---

## Quick Start Guide

### 1. Text Encryption & Decryption
```python
import encryptorx

# Direct mode (self-contained token with synthetic nonce and Poly1305 AEAD)
token = encryptorx.encrypt("Confidential mission payload 2026.")
plaintext = encryptorx.decrypt(token)
print(plaintext)

# Password-protected mode with Memory-Hard Scrypt wrapping
secure_token = encryptorx.encrypt("Restricted document", password="MasterPassphrase#2026")
restored = encryptorx.decrypt(secure_token, password="MasterPassphrase#2026")
print(restored)

# Decryption with strict authentication enforcement
verified = encryptorx.decrypt(token, strict=True)
```

### 2. Custom 256-Bit Key Encryption
```python
import encryptorx
import os

key = os.urandom(32)
# Generates URL-safe Base64 token with RFC 8439 AEAD
b64_token = encryptorx.encrypt("High-security data stream", key=key)
recovered = encryptorx.decrypt(b64_token, key=key)
```

### 3. File Encryption & Decryption
```python
import encryptorx

# Encrypt file with ChaCha20-Poly1305 AEAD (v3 format)
enc_path = encryptorx.encrypt_file("financial_records.pdf", password="SafePassword123")

# Decrypt and authenticate file
dec_path = encryptorx.decrypt_file(enc_path, password="SafePassword123")
```

### 4. Modern Symmetric Ciphers (ChaCha20-Poly1305 & AES-256-GCM)
```python
import encryptorx
import os

key = os.urandom(32)
nonce = os.urandom(12)
payload = b"Direct raw byte buffer."
aad = b"associated-metadata-header"

# ChaCha20-Poly1305 AEAD
ciphertext, tag = encryptorx.chacha20_poly1305_encrypt(key, nonce, payload, aad)
plain = encryptorx.chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)

# AES-256-GCM AEAD
aes_cipher, aes_tag = encryptorx.aes256_gcm_encrypt(key, nonce, payload, aad)
aes_plain = encryptorx.aes256_gcm_decrypt(key, nonce, aes_cipher, aes_tag, aad)
```

### 5. Asymmetric Cryptography (X25519 ECDH & Ed25519 Signatures)
```python
import encryptorx

# Key exchange
alice_priv, alice_pub = encryptorx.generate_x25519_keypair()
bob_priv, bob_pub = encryptorx.generate_x25519_keypair()

secret_alice = encryptorx.derive_shared_secret(alice_priv, bob_pub)
secret_bob = encryptorx.derive_shared_secret(bob_priv, alice_pub)
assert secret_alice == secret_bob

# Digital signatures
sign_priv, sign_pub = encryptorx.generate_signing_keypair()
msg = b"Irrevocable authorization agreement."
signature = encryptorx.ed25519_sign(sign_priv, msg)
is_valid = encryptorx.ed25519_verify(sign_pub, msg, signature)
assert is_valid
```

### 6. Shamir's Secret Sharing (k, n)
```python
import encryptorx

# Split sensitive root key into 5 shares requiring any 3 to reconstruct
secret = "RootMasterAuthorizationKey_9901"
shares = encryptorx.split_secret(secret, k=3, n=5)

# Combine any subset of 3 shares
reconstructed = encryptorx.combine_shares([shares[0], shares[2], shares[4]]).decode("utf-8")
assert reconstructed == secret
```

### 7. Encrypted Container Vault (.vault) with MFA
```python
import encryptorx

# Generate cryptographic keyfile
encryptorx.generate_keyfile("admin.keyfile")

# Package directory into encrypted container
encryptorx.create_vault(
    source_dir="./confidential_project",
    vault_path="project.vault",
    password="VaultPassphrase2026!",
    keyfile_path="admin.keyfile",
    cipher="chacha20"
)

# Inspect container manifest in memory
manifest = encryptorx.inspect_vault("project.vault", password="VaultPassphrase2026!", keyfile_path="admin.keyfile")
print(manifest["files"])

# Extract container
encryptorx.extract_vault("project.vault", output_dir="./restored_project", password="VaultPassphrase2026!", keyfile_path="admin.keyfile")
```

### 8. FIPS 140-2 Randomness & Entropy Audit
```python
import encryptorx
import os

sample = os.urandom(2500)
report = encryptorx.audit_randomness(sample)
print("Shannon Entropy:", report["shannon_entropy"])
print("FIPS 140-2 Passed:", report["all_passed"])
```

### 9. Image Steganography with Cycle-Walking LSB
```python
import encryptorx

# Conceal text inside PNG image
result = encryptorx.hide_text(
    carrier_image_path="cover.png",
    text="Secret message.",
    output_image_path="stego.png",
    password="StegoPassword"
)
print(f"PSNR: {result['psnr_db']:.2f} dB")

# Extract text
extracted = encryptorx.extract_text("stego.png", password="StegoPassword")
```

---

## Cryptographic Security Specification

| Layer | Primitive | Specification | Standard |
| :--- | :--- | :--- | :--- |
| **Symmetric AEAD** | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce, 128-bit MAC tag | RFC 8439 |
| **Synthetic Nonce** | HMAC-SHA256 SIV | $N = \text{HMAC-SHA256}(K, R_{16} \parallel M)[:12]$ | RFC 2104 / SIV |
| **Password KDF (Memory-Hard)** | Scrypt | $N=16384, r=8, p=1$, dklen=32 | RFC 7914 |
| **Password KDF (Standard)** | PBKDF2-HMAC-SHA256 | 600,000 iterations (OWASP Standard) | RFC 8018 |
| **Asymmetric ECDH** | X25519 | Curve25519 Montgomery form, 256-bit key | RFC 7748 |
| **Digital Signatures** | Ed25519 | Edwards-curve Digital Signature Algorithm | RFC 8032 |
| **Secret Sharing** | Shamir Scheme | $(k, n)$ threshold scheme over Galois Field $\text{GF}(256)$ | Shamir (1979) |
| **Transport Steganography** | 64 Symbolic Wrappers | Nonce-masked key and ciphertext transport layer | Proprietary Transport |

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
