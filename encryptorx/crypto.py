"""
Core encryption / decryption logic for the encryptorx library.

Uses a custom stream cipher built on SHA-256 with a 128-bit random nonce.
Ciphertext is returned as URL-safe Base64 so it is safe to embed in JSON,
HTML, URLs, or plain text files.
"""
from __future__ import annotations

import os
import re
import hashlib
import base64
import random
from pathlib import Path

try:
    import EncryptorX as _core
except ImportError:
    import sys
    _parent = Path(__file__).resolve().parent.parent
    if str(_parent) not in sys.path:
        sys.path.insert(0, str(_parent))
    try:
        import EncryptorX as _core
    except ImportError:
        _core = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_NONCE_SIZE = 16  # 128-bit nonce
_DEFAULT_KEY_DIR  = Path(os.path.expanduser("~")) / ".encryptorx"
_DEFAULT_KEY_FILE = _DEFAULT_KEY_DIR / "key.key"
SEPARATORS = ['$', '%', '&', '#', '?']
DEFAULT_SEPARATOR = '$'


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """
    Generate a cryptographically-random 256-bit (32-byte) key.

    Returns:
        32 random bytes suitable for use as an encryption key.

    Example:
        >>> import encryptorx
        >>> key = encryptorx.generate_key()
        >>> len(key)
        32
    """
    return os.urandom(32)


def save_key(key: bytes, path: str | Path | None = None) -> Path:
    """
    Save a key to disk.

    Args:
        key:  The 32-byte key to save.
        path: File path to write to. Defaults to ``~/.encryptorx/key.key``.

    Returns:
        The resolved Path where the key was saved.

    Raises:
        ValueError: If the key is not exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes.")
    dest = Path(path) if path else _DEFAULT_KEY_FILE
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(key)
    return dest


def load_key(path: str | Path | None = None) -> bytes:
    """
    Load a key from disk, generating and saving a new one if it does not exist.

    Args:
        path: File path to read from. Defaults to ``~/.encryptorx/key.key``.

    Returns:
        The 32-byte key.

    Raises:
        ValueError: If the file exists but does not contain a 32-byte key.
    """
    src = Path(path) if path else _DEFAULT_KEY_FILE
    if src.exists():
        key = src.read_bytes()
        if len(key) != 32:
            raise ValueError(f"Key file '{src}' is corrupt (expected 32 bytes, got {len(key)}).")
        return key
    # Auto-generate a new key and persist it
    key = generate_key()
    save_key(key, src)
    return key


# ---------------------------------------------------------------------------
# Internal cipher primitives
# ---------------------------------------------------------------------------

def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a pseudo-random keystream via SHA-256 counter mode."""
    keystream = b""
    counter = 0
    while len(keystream) < length:
        h = hashlib.sha256(key + nonce + counter.to_bytes(4, "big"))
        keystream += h.digest()
        counter += 1
    return keystream[:length]


def _xor_bytes(data: bytes, keystream: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, keystream))


def _raw_encrypt(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(_NONCE_SIZE)
    ks    = _generate_keystream(key, nonce, len(data))
    return nonce + _xor_bytes(data, ks)


def _raw_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) < _NONCE_SIZE:
        raise ValueError("Ciphertext is too short – it may be corrupted.")
    nonce = data[:_NONCE_SIZE]
    body  = data[_NONCE_SIZE:]
    ks    = _generate_keystream(key, nonce, len(body))
    return _xor_bytes(body, ks)


# ---------------------------------------------------------------------------
# Symbolic-Obfuscated Cipher Primitives (XOR-Encrypted in Source)
# ---------------------------------------------------------------------------

_OBFUSCATED_KEY = bytes([
    0x5A, 0xC3, 0x91, 0x47, 0x1E, 0x88, 0x62, 0xF5, 0x33, 0xAA, 0x09, 0x7D, 0xB6, 0x44, 0x2C, 0x9F
])

_OBFUSCATED_SYMBOLIC_BLOB = bytes([
    0x01, 0xf3, 0xca, 0x58, 0x43, 0xb8, 0x3f, 0xeb, 0x68, 0x9b, 0x52, 0x62,
    0xeb, 0x75, 0x71, 0x81, 0x01, 0xf1, 0xca, 0x58, 0x43, 0xba, 0x3f, 0xeb,
    0x68, 0x99, 0x52, 0x62, 0xeb, 0x77, 0x71, 0x81, 0x21, 0xf7, 0xea, 0x58,
    0x63, 0xbc, 0x1f, 0xeb, 0x48, 0x9f, 0x72, 0x62, 0xcb, 0x71, 0x51, 0x81,
    0x21, 0xf5, 0xea, 0x58, 0x63, 0xbe, 0x1f, 0xeb, 0x48, 0x9d, 0x72, 0x62,
    0xcb, 0x73, 0x51, 0x81, 0x72, 0xfb, 0xb9, 0x58, 0x37, 0xb0, 0x4b, 0xeb,
    0x1b, 0x93, 0x21, 0x62, 0x9f, 0x7d, 0x05, 0x81, 0x01, 0xf3, 0xcc, 0x58,
    0x45, 0xb8, 0x3f, 0xeb, 0x48, 0x9b, 0x74, 0x62, 0xcd, 0x75, 0x51, 0x81,
    0x72, 0xf1, 0xb8, 0x58, 0x36, 0xba, 0x4b, 0xeb, 0x0f, 0x99, 0x37, 0x62,
    0x8a, 0x77, 0x12, 0x81, 0x01, 0xf7, 0xcc, 0x58, 0x45, 0xbc, 0x3f, 0xeb,
    0x48, 0x9f, 0x74, 0x62, 0xcd, 0x71, 0x51, 0x81, 0x66, 0xbf, 0x8e, 0x3b,
    0x20, 0x96, 0x5e, 0xc8, 0x2c, 0x97, 0x37, 0x63, 0x8a, 0x69, 0x33, 0xb2,
    0x64, 0xdd, 0xad, 0x39, 0x01, 0xf6, 0x5c, 0xeb, 0x0f, 0x81, 0x16, 0x56,
    0x88, 0x5a, 0x10, 0xa3, 0x45, 0xfd, 0xaf, 0x59, 0x20, 0xb6, 0x7d, 0xc9,
    0x0f, 0xb4, 0x37, 0x01, 0xa9, 0x38, 0x10, 0x81, 0x66, 0xe9, 0x8e, 0x6d,
    0x20, 0x96, 0x5e, 0xab, 0x2c, 0xf4, 0x37, 0x63, 0x8a, 0x04, 0x33, 0xdf,
    0x64, 0xdd, 0xad, 0x66, 0x01, 0xa9, 0x5c, 0xeb, 0x4d, 0xd4, 0x16, 0x03,
    0xc8, 0x5a, 0x72, 0xc1, 0x45, 0x9d, 0xcf, 0x59, 0x34, 0xa2, 0x7d, 0xdf,
    0x19, 0xb4, 0x22, 0x56, 0xa9, 0x6f, 0x07, 0x81, 0x67, 0xfe, 0x8e, 0x7a,
    0x23, 0x96, 0x58, 0xcf, 0x2c, 0x90, 0x33, 0x63, 0x8d, 0x7f, 0x33, 0xa4,
    0x61, 0xdd, 0xed, 0x3b, 0x01, 0xf4, 0x1e, 0xeb, 0x12, 0xd4, 0x28, 0x62,
    0x97, 0x3a, 0x0d, 0x81, 0x65, 0xe9, 0xae, 0x58, 0x21, 0xa2, 0x5d, 0xeb,
    0x73, 0xf4, 0x49, 0x62, 0xf6, 0x1a, 0x6c, 0x81, 0x71, 0xf9, 0xba, 0x58,
    0x35, 0xb2, 0x49, 0xeb, 0x12, 0x9a, 0x28, 0x62, 0x97, 0x74, 0x0d, 0x81,
    0x65, 0xf2, 0xae, 0x58, 0x21, 0xb9, 0x5d, 0xeb, 0x19, 0x98, 0x23, 0x62,
    0x9c, 0x76, 0x06, 0x81, 0x04, 0xf0, 0xcf, 0x58, 0x40, 0xbb, 0x3c, 0xeb,
    0x73, 0x9e, 0x49, 0x62, 0xf6, 0x70, 0x6c, 0x81, 0x24, 0xf6, 0xef, 0x58,
    0x60, 0xbd, 0x1c, 0xeb, 0x09, 0x9c, 0x33, 0x62, 0x8c, 0x72, 0x16, 0x81,
    0x61, 0xf4, 0xaa, 0x58, 0x25, 0xbf, 0x59, 0xeb, 0x18, 0x92, 0x22, 0x62,
    0x9d, 0x7c, 0x07, 0x81, 0x67, 0xfa, 0xac, 0x58, 0x23, 0xb1, 0x5f, 0xeb,
    0x4f, 0x9a, 0x75, 0x62, 0xca, 0x74, 0x50, 0x81, 0x75, 0xf2, 0xbe, 0x58,
    0x31, 0xb9, 0x4d, 0xeb, 0x4d, 0x90, 0x16, 0x47, 0xc8, 0x5a, 0x72, 0xbe,
    0x45, 0xe2, 0xcf, 0x59, 0x34, 0xa3, 0x7d, 0xde, 0x19, 0xb4, 0x49, 0x40,
    0xa9, 0x79, 0x6c, 0x81, 0x26, 0xbd, 0x8e, 0x39, 0x62, 0x96, 0x3c, 0x8b,
    0x2c, 0xd4, 0x57, 0x63, 0x97, 0x3a, 0x33, 0xe1, 0x7b, 0xdd, 0xae, 0x6c,
    0x01, 0xa3, 0x5d, 0xeb, 0x1b, 0xea, 0x16, 0x3d, 0x9f, 0x5a, 0x57, 0xc1,
    0x45, 0x9d, 0xec, 0x59, 0x22, 0xf6, 0x7d, 0x8b, 0x0d, 0xb4, 0x37, 0x03,
    0xa9, 0x3a, 0x10,
])

_OBFUSCATED_LEGACY_BLOB = bytes([
    0x14, 0x96, 0x8e, 0x0b, 0x52, 0x96, 0x0c, 0x80, 0x2c, 0xc6, 0x65, 0x63,
    0xf8, 0x31, 0x33, 0xf3, 0x36, 0xdd, 0xff, 0x12, 0x01, 0xe4, 0x0e, 0xeb,
    0x7d, 0xff, 0x16, 0x11, 0xda, 0x5a, 0x42, 0xea, 0x45, 0x8f, 0xdd, 0x59,
    0x50, 0xfd, 0x7d, 0xb9, 0x7f, 0xb4, 0x67, 0x28, 0xa9, 0x08, 0x60, 0x81,
    0x14, 0x96, 0x8e, 0x0b, 0x72, 0x96, 0x0c, 0x80, 0x2c, 0xe6, 0x65, 0x63,
    0xf8, 0x31, 0x33, 0xf3, 0x16, 0xdd, 0xdf, 0x12, 0x01, 0xe4, 0x2e, 0xeb,
    0x7f, 0xe6, 0x16, 0x31, 0xfa, 0x5a, 0x40, 0xf3, 0x45, 0xaf, 0xfd, 0x59,
    0x52, 0xe4, 0x7d, 0x99, 0x5f, 0xb4, 0x65, 0x31, 0xa9, 0x28, 0x40, 0x81,
    0x16, 0x8f, 0x8e, 0x2b, 0x72, 0x96, 0x0e, 0x99, 0x2c, 0xe6, 0x45, 0x63,
    0xfa, 0x28, 0x33, 0xd3, 0x16, 0xdd, 0xfd, 0x0b, 0x01, 0xc4, 0x2e, 0xeb,
    0x5d, 0xb5, 0x7c, 0x11, 0xda, 0x5a, 0x62, 0x80, 0x2f, 0xaf, 0xfd, 0x59,
    0x70, 0x97, 0x37, 0xb9, 0x7f, 0xb4, 0x47, 0x62, 0xe3, 0x08, 0x60, 0x81,
    0x34, 0xdc, 0xc4, 0x2b, 0x72, 0x96, 0x2c, 0xea, 0x46, 0xe6, 0x65, 0x63,
    0xd8, 0x5b, 0x59, 0xf3, 0x16, 0xdd, 0xdf, 0x58, 0x4b, 0xe4, 0x2e, 0xeb,
    0x5d, 0xdf, 0x16, 0x11, 0xa8, 0x0a, 0x79, 0x80, 0x16, 0xdd, 0xdf, 0x32,
    0x01, 0xc4, 0x7c, 0x9b, 0x66, 0xb5, 0x65, 0x63, 0xd8, 0x31, 0x40, 0xf3,
    0x45, 0xad, 0xe4, 0x2b, 0x72, 0x96, 0x2c, 0xa0, 0x7f, 0xe6, 0x16, 0x33,
    0xe3, 0x08, 0x60, 0x81, 0x14, 0xb6, 0xfd, 0x2b, 0x01, 0xc6, 0x17, 0x99,
    0x5f, 0xb4, 0x67, 0x28, 0xfa, 0x08, 0x33, 0xf1, 0x0f, 0x8f, 0xdd, 0x59,
    0x50, 0xfd, 0x0e, 0xb9, 0x2c, 0xe4, 0x7c, 0x11, 0xfa, 0x5a, 0x42, 0xea,
    0x16, 0x8f, 0x8e, 0x29, 0x6b, 0xc4, 0x2e, 0xeb, 0x7d, 0xff, 0x65, 0x11,
    0xa9, 0x0a, 0x79, 0xf3, 0x36, 0xdd, 0xff, 0x32, 0x72, 0xc4, 0x7d, 0x9b,
    0x46, 0xc6, 0x45, 0x63, 0xd8, 0x31, 0x40, 0xf3, 0x45, 0x8d, 0xc4, 0x0b,
    0x52, 0x96, 0x2c, 0xa0, 0x7f, 0xe6, 0x16, 0x13, 0xc3, 0x28, 0x40, 0x81,
    0x14, 0xb6, 0xfd, 0x2b, 0x01, 0xc6, 0x37, 0xb9, 0x7f, 0xb4, 0x47, 0x28,
    0xfa, 0x08, 0x33, 0xd1, 0x2f, 0xaf, 0xfd, 0x59, 0x50, 0xc4, 0x7d, 0xa0,
    0x7f, 0xb4, 0x67, 0x11, 0xa9, 0x31, 0x40, 0x81, 0x14, 0xaf, 0x8e, 0x32,
    0x52, 0x96, 0x0c, 0xb9, 0x2c, 0xff, 0x65, 0x63, 0xf8, 0x08, 0x33, 0xea,
    0x36, 0xdd, 0xff, 0x2b, 0x01, 0xdd, 0x2e, 0xeb, 0x66, 0xe6, 0x16, 0x33,
    0xfa, 0x5a, 0x59, 0xf3, 0x45, 0xad, 0xfd, 0x59, 0x4b, 0xe4, 0x7d, 0xbb,
    0x5f, 0xb4, 0x7c, 0x31, 0xa9, 0x2a, 0x60, 0x81, 0x0f, 0x8d, 0x8e, 0x0b,
    0x52, 0x96, 0x17, 0x9b, 0x2c, 0xc6, 0x65, 0x63, 0xe3, 0x2a, 0x33, 0xf3,
    0x36, 0xdd, 0xe4, 0x09, 0x01, 0xc4, 0x2e, 0xeb, 0x7f, 0xe6, 0x16, 0x28,
    0xf8, 0x5a, 0x40, 0xf3, 0x45, 0xb6, 0xff, 0x59, 0x52, 0xe4, 0x7d, 0x80,
    0x5d, 0xb4, 0x65, 0x31, 0xa9, 0x11, 0x62, 0x81, 0x14, 0x96, 0xdd, 0x58,
    0x52, 0x96, 0x0c, 0x80, 0x5f, 0xb5, 0x65,
])

def _unpack_obfuscated_wrappers(blob: bytes, key: bytes):
    raw = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob)).decode("utf-8")
    return [tuple(chunk.split("\x1f")) for chunk in raw.split("\x1e")]

SYMBOLIC_WRAPPERS = _unpack_obfuscated_wrappers(_OBFUSCATED_SYMBOLIC_BLOB, _OBFUSCATED_KEY)
_LEGACY_NULL_WRAPPERS = _unpack_obfuscated_wrappers(_OBFUSCATED_LEGACY_BLOB, _OBFUSCATED_KEY)
_ALL_WRAPPERS = SYMBOLIC_WRAPPERS + _LEGACY_NULL_WRAPPERS

_DEOBFUSCATE_REGEX = re.compile(
    r'(?:' + '|'.join(f'{re.escape(pre)}([0-9a-fA-F]{{2}}){re.escape(post)}' for pre, post in _ALL_WRAPPERS) + r')'
)

def _generate_random_noise(min_len: int = 2, max_len: int = 6) -> str:
    safe_noise = "abcdefghjkmopqrstwxyzABCDEFGHJKMOPQRSTWXYZ"
    length = random.randint(min_len, max_len)
    return ''.join(random.choice(safe_noise) for _ in range(length))

def _obfuscate_byte_hex_chunks(hex_str: str) -> str:
    chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    obfuscated_parts = []
    connectors = ["=", "_", "-", "~", "+", ""]
    for chunk in chunks:
        pre_noise = _generate_random_noise(2, 5)
        post_noise = _generate_random_noise(2, 5)
        pre_wrap, post_wrap = random.choice(SYMBOLIC_WRAPPERS)
        wrapped = f"{pre_wrap}{chunk}{post_wrap}"
        connector = random.choice(connectors)
        obfuscated_parts.append(f"{pre_noise}{connector}{wrapped}{connector}{post_noise}")
    return "".join(obfuscated_parts)

def _deobfuscate_byte_hex(obfuscated_str: str) -> str:
    matches = _DEOBFUSCATE_REGEX.findall(obfuscated_str)
    return "".join(m for m in matches if m)

# ---------------------------------------------------------------------------
# Public text API
# ---------------------------------------------------------------------------

def encrypt(
    text: str,
    key: bytes | None = None,
    delimiter: str | None = None,
    password: str | None = None,
) -> str:
    """
    Encrypt a plain-text string.
    If password is provided, uses PBKDF2-HMAC-SHA256 authenticated encryption.
    By default, produces a self-contained Null-Obfuscated Cipher bundle.
    If a specific key is passed, produces standard URL-safe Base64.
    """
    if not text:
        return ""
    if key is not None:
        _key = _resolve_key(key)
        raw = _raw_encrypt(text.encode("utf-8"), _key)
        return base64.urlsafe_b64encode(raw).decode("utf-8")

    if _core is not None:
        return _core.encrypt(text, password=password, delimiter=delimiter)

    if delimiter not in SEPARATORS:
        delimiter = DEFAULT_SEPARATOR
    
    key_bytes = os.urandom(32)
    key_hex = key_bytes.hex()
    payload_bytes = _raw_encrypt(text.encode("utf-8"), key_bytes)
    payload_hex = payload_bytes.hex()
    
    obf_key = _obfuscate_byte_hex_chunks(key_hex)
    obf_payload = _obfuscate_byte_hex_chunks(payload_hex)
    return f"{obf_key}{delimiter}{obf_payload}"

def decrypt(
    ciphertext: str,
    key: bytes | None = None,
    password: str | None = None,
    strict: bool = False,
) -> str:
    """
    Decrypt a ciphertext string.
    Automatically detects Null-Obfuscated bundles and recovers embedded keys,
    verifies HMAC tags, and uses password if protected.
    Fault-tolerant: recovers and shows decrypted text even if characters or info are partially lost.
    """
    if not ciphertext:
        return ""

    if key is not None:
        _key = _resolve_key(key)
        try:
            raw = base64.urlsafe_b64decode(ciphertext)
            return _raw_decrypt(raw, _key).decode("utf-8", errors="replace")
        except (ValueError, base64.binascii.Error) as e:
            if strict:
                raise ValueError("Decryption failed: wrong key or corrupted ciphertext.") from e
            return ""

    if _core is not None:
        return _core.decrypt(ciphertext, password=password, strict=strict)
    
    stripped = ciphertext.strip()
    found_sep = None
    for sep in SEPARATORS:
        if sep in stripped:
            found_sep = sep
            break
            
    if found_sep and key is None:
        parts = stripped.split(found_sep, 1)
        if len(parts) != 2:
            if strict:
                raise ValueError("Invalid format: ciphertext missing two sections.")
            return ""
        obf_key, obf_payload = parts
        key_hex = _deobfuscate_byte_hex(obf_key)
        if len(key_hex) != 64:
            if strict:
                raise ValueError(f"Corrupted key: expected 64 hex, got {len(key_hex)}.")
            key_hex = key_hex.ljust(64, "0")[:64]
        key_bytes = bytes.fromhex(key_hex)
        payload_hex = _deobfuscate_byte_hex(obf_payload)
        payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""
        return _raw_decrypt(payload_bytes, key_bytes).decode("utf-8", errors="replace")
        
    _key = _resolve_key(key)
    try:
        raw = base64.urlsafe_b64decode(ciphertext)
        return _raw_decrypt(raw, _key).decode("utf-8", errors="replace")
    except (ValueError, base64.binascii.Error) as e:
        if strict:
            raise ValueError("Decryption failed: wrong key or corrupted ciphertext.") from e
        return ""



# ---------------------------------------------------------------------------
# Public file API
# ---------------------------------------------------------------------------

def encrypt_file(
    file_path: str | Path,
    output_path: str | Path | None = None,
    key: bytes | None = None,
    password: str | None = None,
) -> Path:
    """
    Encrypt a file and write the result to disk (.enc).
    Supports password protection with PBKDF2 and HMAC.
    """
    if key is None and _core is not None:
        return _core.encrypt_file(file_path, output_path=output_path, password=password)

    src  = Path(file_path)
    dest = Path(output_path) if output_path else Path(f"{src}.enc")
    _key = _resolve_key(key)

    if src.stat().st_size > 500 * 1024 * 1024:
        raise ValueError("File exceeds the 500 MB limit.")

    try:
        raw_data = src.read_bytes()
        dest.write_bytes(_raw_encrypt(raw_data, _key))
        return dest
    except IOError as e:
        raise IOError(f"Could not encrypt '{src}': {e}") from e


def decrypt_file(
    file_path: str | Path,
    output_path: str | Path | None = None,
    key: bytes | None = None,
    password: str | None = None,
) -> Path:
    """
    Decrypt a file that was encrypted by :func:`encrypt_file`.
    Supports password protection with PBKDF2 and HMAC integrity validation.
    """
    if key is None and _core is not None:
        return _core.decrypt_file(file_path, output_path=output_path, password=password)

    src  = Path(file_path)
    _key = _resolve_key(key)

    if output_path:
        dest = Path(output_path)
    else:
        name = src.name
        dest = src.parent / (name[:-4] if name.lower().endswith(".enc") else f"{name}.dec")

    # Avoid overwriting existing files
    if dest.exists():
        base_stem = dest.stem
        suffix    = dest.suffix
        i = 1
        while dest.exists():
            dest = dest.parent / f"{base_stem}.dec({i}){suffix}"
            i += 1

    try:
        raw_data = src.read_bytes()
        dest.write_bytes(_raw_decrypt(raw_data, _key))
        return dest
    except (IOError, ValueError) as e:
        raise ValueError(f"Could not decrypt '{src}': {e}") from e


def generate_secure_password(length: int = 24) -> str:
    """Generate a high-entropy cryptographically secure password."""
    if _core is not None and hasattr(_core, "generate_secure_password"):
        return _core.generate_secure_password(length)
    import secrets
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return "".join(secrets.choice(chars) for _ in range(length))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_key(key: bytes | None) -> bytes:
    """Return the provided key or load the default one from disk."""
    if key is None:
        return load_key()
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes.")
    return key
