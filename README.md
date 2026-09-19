# EncryptorX

[![PyPI version](https://img.shields.io/pypi/v/encryptorx.svg)](https://pypi.org/project/encryptorx/)
[![Python versions](https://img.shields.io/pypi/pyversions/encryptorx.svg)](https://pypi.org/project/encryptorx/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A high-performance cryptographic and steganographic suite for Python, providing authenticated stream encryption and carrier-invariant image steganography through cycle-walking pseudo-random pixel permutation.

---

## Overview

EncryptorX is designed for secure, tamper-resistant data concealment and cryptographic transmission. It combines an authenticated symmetric stream cipher with an image steganography engine that eliminates structural clustering artifacts typical of linear least significant bit (LSB) insertion.

### Key Capabilities

- **Authenticated Encryption**: Encrypt-then-MAC architecture utilizing PBKDF2-HMAC-SHA256 (100,000 iterations standard) and a 256-bit symmetric stream cipher. Tampering or incorrect authentication credentials immediately abort extraction prior to processing.
- **Cryptographic Pixel Shuffling**: Full-period pseudo-random bijective permutation governed by the Hull-Dobell theorem. Data bits are distributed pseudorandomly across carrier pixels, resisting chi-square ($\chi^2$) analysis, sample pair analysis, and bit-plane inspection.
- **Carrier Invariance**: Dimensions, color space parameters, and alpha channels (transparency) are preserved without perceptible degradation (Peak Signal-to-Noise Ratio consistently exceeding 65 dB at default configuration).
- **Multi-Payload Support**: Embedding and extraction of raw text strings or arbitrary binary objects (PDF, ZIP, executables, audio) with automated filename and size metadata recovery.
- **Standalone Stream Cipher**: Pure Python cryptographic routines with 128-bit randomized nonces and URL-safe Base64 serialized ciphertext.

---

## Installation

### Standard Installation

```bash
pip install encryptorx
```

### Full Installation (NumPy Acceleration)

```bash
pip install encryptorx[full]
```

---

## Quick Start

### 1. Image Steganography: Text Concealment

```python
import encryptorx

# Embed encrypted text into a carrier image
result = encryptorx.hide_text(
    carrier_image="cover.png",
    output_image="stego.png",
    text="Confidential data payload.",
    password="DesignatedPassphrase"
)

print(f"PSNR: {result['psnr']:.2f} dB, Payload: {result['payload_bytes']} bytes")

# Extract and authenticate payload
recovered_text = encryptorx.extract_text(
    stego_image="stego.png",
    password="DesignatedPassphrase"
)

print(f"Recovered: {recovered_text}")
```

### 2. Image Steganography: Binary File Concealment

```python
import encryptorx

# Conceal an arbitrary binary file (e.g., PDF, ZIP, archive) inside a PNG carrier
encryptorx.hide_file(
    carrier_image="cover.png",
    output_image="stego.png",
    file_to_hide="document.pdf",
    password="DesignatedPassphrase"
)

# Extract and restore the original file with verified integrity
extracted_path = encryptorx.extract_file(
    stego_image="stego.png",
    output_dir="./restored",
    password="DesignatedPassphrase"
)

print(f"File restored to: {extracted_path}")
```

### 3. Symmetric Cryptography: Data and File Encryption

```python
import encryptorx

# Encrypt text using an automatically derived or persistent key
ciphertext = encryptorx.encrypt("Sensitive configuration string")
plaintext  = encryptorx.decrypt(ciphertext)

# Encrypt using an explicit 256-bit key
key = encryptorx.generate_key()
token = encryptorx.encrypt("Target plaintext", key=key)
recovered = encryptorx.decrypt(token, key=key)

# Direct binary file encryption
encryptorx.encrypt_file("database.sqlite")       # Produces database.sqlite.enc
encryptorx.decrypt_file("database.sqlite.enc")   # Restores database.sqlite
```

### 4. Utilities

```python
import encryptorx

# Cryptographically secure random password generation
password = encryptorx.generate_secure_password(length=32)

# URL-safe Base64 encoding/decoding
encoded = encryptorx.b64_encode("Data buffer")
decoded = encryptorx.b64_decode(encoded)
```

---

## Technical Specifications

### Steganographic Engine Architecture

| Parameter | Options | Default | Description |
| :--- | :--- | :--- | :--- |
| `bits_per_channel` | `1`, `2`, `4` | `1` | Bit depth per channel. `1` achieves maximum stealth (PSNR > 65 dB); `4` maximizes throughput. |
| `channels` | `"RGB"`, `"B"`, `"R"`, `"G"`, `"RG"`, `"RB"`, `"GB"` | `"RGB"` | Target channels. `"B"` minimizes human eye perceptibility by targeting S-cone frequencies. |
| `shuffle_algorithm`| `"lcg"`, `"prng"` | `"lcg"` | Permutation engine. `"lcg"` uses Hull-Dobell cycle-walking with O(1) auxiliary space. |
| `compress` | `True`, `False` | `True` | Applies adaptive zlib compression prior to encryption. |
| `pbkdf2_rounds` | Positive integer | `100000` | Iteration count for PBKDF2 key derivation. |

### Capacity Calculation

Carrier payload capacity is calculated based on resolution, active channels, and bit depth:

$$\text{Capacity (bytes)} = \left\lfloor \frac{\text{Width} \times \text{Height} \times |\text{Channels}| \times \text{BitsPerChannel}}{8} \right\rfloor - \text{Overhead}$$

```python
import encryptorx

metrics = encryptorx.get_image_capacity("cover.png", bits_per_channel=1, channels="RGB")
print(f"Available capacity: {metrics['capacity_bytes']} bytes ({metrics['capacity_kb']} KB)")
```

---

## Security Model and Guarantees

1. **Authentication Tag Verification**: An HMAC-SHA256 digest is appended to the ciphertext. Any modification of carrier pixel values alters the reconstructed bitstream and triggers an `AuthenticationError`, halting execution before arbitrary memory allocation or parsing occurs.
2. **Cycle-Walking Dispersion**: Eliminates contiguous sequence signatures. Even when embedding small payloads into large images, the bits are distributed across the entirety of the pixel space.
3. **Alpha Channel Integrity**: RGBA images maintain unperturbed alpha values to avoid transparency anomalies in downstream rendering pipelines.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
