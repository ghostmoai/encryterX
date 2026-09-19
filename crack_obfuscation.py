#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
EncryptorX - Obfuscation & Security Audit Suite (100% CPU Multi-Core Engine)
=============================================================================
Author: Antigravity / Security Research
Purpose:
  1. Deobfuscate and reverse the "Null-Obfuscated Cipher" in EncryptorX.
  2. Prove that unprotected tokens (flag 0x00) leak the encryption key directly.
  3. Execute multi-core parallel brute-force (100% CPU saturation) against
     password-protected tokens (flag 0x01, PBKDF2-HMAC-SHA256 100,000 iterations).
  4. Perform multi-core CPU stress testing and cryptanalytic throughput benchmarks.
=============================================================================
"""

from __future__ import annotations

import os
import sys
import time
import math
import hmac
import itertools
import string
import hashlib
import argparse
import multiprocessing as mp
from typing import Optional, Tuple, List, Dict, Any

# ---------------------------------------------------------------------------
# Global Protocol Specifications (from EncryptorX)
# ---------------------------------------------------------------------------
NONCE_SIZE = 16       # 128-bit Nonce
KEY_SIZE = 32         # 256-bit Key
TAG_SIZE = 16         # 128-bit HMAC-SHA256 Auth Tag
SALT_SIZE = 16        # 128-bit PBKDF2/Scrypt Salt
PBKDF2_ROUNDS = 600_000
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1

FLAG_DIRECT = 0x00
FLAG_PBKDF2 = 0x01
FLAG_SCRYPT = 0x02

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

SYMBOLIC_WRAPPERS: List[Tuple[str, str]] = _unpack_obfuscated_wrappers(_OBFUSCATED_SYMBOLIC_BLOB, _OBFUSCATED_KEY)
_LEGACY_NULL_WRAPPERS: List[Tuple[str, str]] = _unpack_obfuscated_wrappers(_OBFUSCATED_LEGACY_BLOB, _OBFUSCATED_KEY)
_ALL_WRAPPERS = SYMBOLIC_WRAPPERS + _LEGACY_NULL_WRAPPERS

import re
_DEOBF_REGEX = re.compile(
    r'(?:' + '|'.join(f'{re.escape(pre)}([0-9a-fA-F]{{2}}){re.escape(post)}' for pre, post in _ALL_WRAPPERS) + r')'
)

# Blind heuristic regex: detects hex bytes sandwiched between non-alphabetic symbols/digits
_BLIND_HEX_REGEX = re.compile(r'[^a-zA-Z$%&#]{1,4}([0-9a-fA-F]{2})[^a-zA-Z$%&#]{1,4}')

# ---------------------------------------------------------------------------
# Cryptographic Primitives (Matching EncryptorX)
# ---------------------------------------------------------------------------

def generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generates a SHA-256 counter-mode keystream."""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        h = hashlib.sha256(key + nonce + counter.to_bytes(4, 'big'))
        keystream.extend(h.digest())
        counter += 1
    return bytes(keystream[:length])

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bitwise XOR between two byte sequences."""
    return bytes(x ^ y for x, y in zip(a, b))

def derive_auth_key(key: bytes) -> bytes:
    """Derives HMAC authentication key."""
    return hashlib.sha256(b"ENCRYPTORX_AUTH_TAG_SALT:" + key).digest()

# ---------------------------------------------------------------------------
# Deobfuscation Algorithms
# ---------------------------------------------------------------------------

def deobfuscate_known_wrappers(obfuscated_str: str) -> str:
    """Extracts hex characters using precompiled catalogue of 64 NULL wrappers."""
    return "".join(next(g for g in m.groups() if g is not None) for m in _DEOBF_REGEX.finditer(obfuscated_str))

def deobfuscate_blind_heuristic(obfuscated_str: str) -> str:
    """
    Blindly breaks obfuscation WITHOUT knowing the 64 wrapper list.
    Exploits the structural flaw: noise characters ('qwrtpsdfghjkmzxcv123456789')
    never contain 'n, u, l, N, U, L', allowing instant boundary isolation.
    """
    matches = _BLIND_HEX_REGEX.findall(obfuscated_str)
    return "".join(matches)

# ---------------------------------------------------------------------------
# Token Parser & Structural Analyzer
# ---------------------------------------------------------------------------

class TokenStructure:
    def __init__(self, raw_token: str, use_blind_deobfuscation: bool = False):
        self.raw_token = raw_token.strip()
        self.use_blind = use_blind_deobfuscation
        self.is_multi_separator = False
        self.is_legacy_separator = False
        self.delimiter = None

        self.nonce_bytes: Optional[bytes] = None
        self.auth_tag: Optional[bytes] = None
        self.ciphertext_bytes: Optional[bytes] = None
        self.masked_key_package: Optional[bytes] = None
        self.raw_key_package: Optional[bytes] = None
        self.is_password_protected: bool = False
        self.salt: Optional[bytes] = None
        self.enc_key: Optional[bytes] = None
        self.plaintext_key: Optional[bytes] = None

        self._parse()

    def _deobf(self, text: str) -> str:
        if self.use_blind:
            return deobfuscate_blind_heuristic(text)
        return deobfuscate_known_wrappers(text)

    def _parse(self):
        # 1. Multi-separator token ($ % & #)
        if all(s in self.raw_token for s in ['$', '%', '&', '#']):
            self.is_multi_separator = True
            p_key, rest1 = self.raw_token.split('$', 1)
            p_nonce, rest2 = rest1.split('%', 1)
            p_tag, rest3 = rest2.split('&', 1)
            p_cipher, _p_crc = rest3.split('#', 1)

            self.nonce_bytes = bytes.fromhex(self._deobf(p_nonce))
            self.auth_tag = bytes.fromhex(self._deobf(p_tag))
            self.ciphertext_bytes = bytes.fromhex(self._deobf(p_cipher))
            masked_hex = self._deobf(p_key)
            self.masked_key_package = bytes.fromhex(masked_hex)

        else:
            # 2. Legacy single-separator token
            for sep in ['$', '%', '&', '#']:
                if sep in self.raw_token:
                    self.is_legacy_separator = True
                    self.delimiter = sep
                    break

            if not self.is_legacy_separator:
                raise ValueError("Token no reconocido: no contiene delimitadores validos de EncryptorX.")

            p_key, p_payload = self.raw_token.split(self.delimiter, 1)
            self.masked_key_package = bytes.fromhex(self._deobf(p_key))
            payload_bytes = bytes.fromhex(self._deobf(p_payload))

            if len(payload_bytes) < NONCE_SIZE + TAG_SIZE:
                raise ValueError("Payload demasiado corto.")

            self.nonce_bytes = payload_bytes[:NONCE_SIZE]
            self.auth_tag = payload_bytes[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
            self.ciphertext_bytes = payload_bytes[NONCE_SIZE + TAG_SIZE:]

        # 3. Unmask key package using nonce
        mask = generate_keystream(self.nonce_bytes, b"ENCRYPTORX_KEY_MASK", len(self.masked_key_package))
        self.raw_key_package = xor_bytes(self.masked_key_package, mask)

        flag = self.raw_key_package[0]
        if flag == 0x00:
            self.is_password_protected = False
            self.plaintext_key = self.raw_key_package[1:1 + KEY_SIZE]
        elif flag in (0x01, 0x02):
            self.is_password_protected = True
            self.kdf_type = "scrypt" if flag == 0x02 else "pbkdf2"
            self.salt = self.raw_key_package[1:1 + SALT_SIZE]
            self.enc_key = self.raw_key_package[1 + SALT_SIZE:1 + SALT_SIZE + KEY_SIZE]
        else:
            raise ValueError(f"Flag desconocido en el paquete de clave: {flag:#x}")

# ---------------------------------------------------------------------------
# Multi-Core Cracking Worker Functions (Top-Level for Windows Pickling)
# ---------------------------------------------------------------------------

def _worker_pin_chunk(
    start_num: int,
    end_num: int,
    pin_len: int,
    salt: bytes,
    enc_key: bytes,
    raw_key_package: bytes,
    nonce_bytes: bytes,
    ciphertext_bytes: bytes,
    target_tag: bytes,
    stop_event: Any,
    result_queue: Any,
    progress_counter: Any,
    kdf_type: str = "scrypt"
):
    """Worker process: tests a range of numeric PINs with 100% CPU core utilization."""
    mac_data = raw_key_package + nonce_bytes + ciphertext_bytes
    local_count = 0
    fmt = f"{{:0{pin_len}d}}"

    for num in range(start_num, end_num):
        if stop_event.is_set():
            break

        candidate = fmt.format(num)
        if kdf_type == "scrypt":
            wrapping_key = hashlib.scrypt(
                candidate.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_SIZE
            )
        else:
            wrapping_key = hashlib.pbkdf2_hmac(
                'sha256', candidate.encode('utf-8'), salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
            )
        key_bytes = xor_bytes(enc_key, generate_keystream(wrapping_key, salt, KEY_SIZE))
        auth_key = hashlib.sha256(b"ENCRYPTORX_AUTH_TAG_SALT:" + key_bytes).digest()
        calc_tag = hmac.new(auth_key, mac_data, hashlib.sha256).digest()[:TAG_SIZE]

        local_count += 1
        if local_count >= 5:
            with progress_counter.get_lock():
                progress_counter.value += local_count
            local_count = 0

        if hmac.compare_digest(target_tag, calc_tag):
            stop_event.set()
            result_queue.put((candidate, key_bytes))
            break

    if local_count > 0:
        with progress_counter.get_lock():
            progress_counter.value += local_count

def _worker_dict_chunk(
    words_chunk: List[str],
    salt: bytes,
    enc_key: bytes,
    raw_key_package: bytes,
    nonce_bytes: bytes,
    ciphertext_bytes: bytes,
    target_tag: bytes,
    stop_event: Any,
    result_queue: Any,
    progress_counter: Any,
    kdf_type: str = "scrypt"
):
    """Worker process: tests candidate words against the token."""
    mac_data = raw_key_package + nonce_bytes + ciphertext_bytes
    local_count = 0

    for candidate in words_chunk:
        if stop_event.is_set():
            break

        if kdf_type == "scrypt":
            wrapping_key = hashlib.scrypt(
                candidate.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_SIZE
            )
        else:
            wrapping_key = hashlib.pbkdf2_hmac(
                'sha256', candidate.encode('utf-8'), salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
            )
        key_bytes = xor_bytes(enc_key, generate_keystream(wrapping_key, salt, KEY_SIZE))
        auth_key = hashlib.sha256(b"ENCRYPTORX_AUTH_TAG_SALT:" + key_bytes).digest()
        calc_tag = hmac.new(auth_key, mac_data, hashlib.sha256).digest()[:TAG_SIZE]

        local_count += 1
        if local_count >= 5:
            with progress_counter.get_lock():
                progress_counter.value += local_count
            local_count = 0

        if hmac.compare_digest(target_tag, calc_tag):
            stop_event.set()
            result_queue.put((candidate, key_bytes))
            break

    if local_count > 0:
        with progress_counter.get_lock():
            progress_counter.value += local_count

def _worker_benchmark_stress(mode: str, rounds_or_n: int, counter: Any, stop_event: Any):
    """Worker process for CPU benchmark stress test (saturates core at 100%)."""
    salt = b"BENCHMARK_SALT16"
    pwd = b"benchmark_password"
    while not stop_event.is_set():
        if mode == "scrypt":
            hashlib.scrypt(pwd, salt=salt, n=rounds_or_n, r=8, p=1, dklen=32)
        else:
            hashlib.pbkdf2_hmac('sha256', pwd, salt, rounds_or_n, dklen=32)
        with counter.get_lock():
            counter.value += 1

# ---------------------------------------------------------------------------
# High-Level Cracking Orchestrator
# ---------------------------------------------------------------------------

class EncryptorXAuditor:
    def __init__(self, num_workers: Optional[int] = None):
        self.num_workers = num_workers or os.cpu_count() or 4

    def break_unprotected(self, token_str: str, blind: bool = False) -> Dict[str, Any]:
        """
        Instantly breaks and decrypts an unprotected token (flag 0x00).
        Reveals that the key was in the token all along.
        """
        t0 = time.perf_counter()
        token = TokenStructure(token_str, use_blind_deobfuscation=blind)

        if token.is_password_protected:
            raise ValueError("El token requiere contrasena; usa el modo de fuerza bruta.")

        # Decrypt ciphertext
        keystream = generate_keystream(token.plaintext_key, token.nonce_bytes, len(token.ciphertext_bytes))
        plaintext = xor_bytes(token.ciphertext_bytes, keystream).decode('utf-8', errors='replace')
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Verify HMAC
        auth_key = derive_auth_key(token.plaintext_key)
        expected_tag = hmac.new(
            auth_key,
            token.raw_key_package + token.nonce_bytes + token.ciphertext_bytes,
            hashlib.sha256
        ).digest()[:TAG_SIZE]
        integrity_ok = hmac.compare_digest(token.auth_tag, expected_tag)

        return {
            "recovered_text": plaintext,
            "recovered_key_hex": token.plaintext_key.hex(),
            "nonce_hex": token.nonce_bytes.hex(),
            "elapsed_ms": elapsed_ms,
            "integrity_verified": integrity_ok,
            "deobfuscation_type": "Blind Heuristic" if blind else "Known Catalog Regex"
        }

    def crack_pin(self, token_str: str, pin_length: int = 4, max_pins: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes parallel multi-core brute-force (100% CPU load) to crack numeric PINs.
        """
        token = TokenStructure(token_str)
        if not token.is_password_protected:
            print("[INFO] El token no tiene contrasena. Descifrando inmediatamente...")
            return self.break_unprotected(token_str)

        total_combinations = 10 ** pin_length if max_pins is None else min(10 ** pin_length, max_pins)
        chunk_size = math.ceil(total_combinations / self.num_workers)

        print(f"\n" + "="*70)
        print(f"[*] INICIANDO FUERZA BRUTA DE PIN ({pin_length} DIGITOS)")
        print(f"[*] Esquema KDF: {token.kdf_type.upper()}")
        if token.kdf_type == "scrypt":
            print(f"[*] Blindaje: Scrypt Memory-Hard (N={SCRYPT_N}, r={SCRYPT_R}, p={SCRYPT_P}, ~16MB RAM/intento)")
        else:
            print(f"[*] Iteraciones PBKDF2: {PBKDF2_ROUNDS:,}")
        print(f"[*] Espacio de busqueda: {total_combinations:,} combinaciones")
        print(f"[*] Nucleos de CPU asignados: {self.num_workers} (100% USO DE CPU)")
        print(f"="*70)

        stop_event = mp.Event()
        result_queue = mp.Queue()
        counter = mp.Value('i', 0)

        processes = []
        for i in range(self.num_workers):
            c_start = i * chunk_size
            c_end = min((i + 1) * chunk_size, total_combinations)
            if c_start >= total_combinations:
                break
            p = mp.Process(
                target=_worker_pin_chunk,
                args=(
                    c_start, c_end, pin_length,
                    token.salt, token.enc_key, token.raw_key_package,
                    token.nonce_bytes, token.ciphertext_bytes, token.auth_tag,
                    stop_event, result_queue, counter, token.kdf_type
                )
            )
            p.daemon = True
            p.start()
            processes.append(p)

        t0 = time.perf_counter()
        found_pin = None
        recovered_key = None

        # Live telemetry display loop
        try:
            while any(p.is_alive() for p in processes):
                if stop_event.is_set():
                    break
                time.sleep(0.4)
                elapsed = time.perf_counter() - t0
                done = counter.value
                rate = done / elapsed if elapsed > 0 else 0
                pct = (done / total_combinations) * 100 if total_combinations > 0 else 0
                sys.stdout.write(
                    f"\r[CPU: 100%] Probados: {done:,}/{total_combinations:,} ({pct:.1f}%) "
                    f"| Velocidad: {rate:.1f} H/s | Tiempo: {elapsed:.1f}s"
                )
                sys.stdout.flush()

            for p in processes:
                p.join(timeout=1.0)

            if not result_queue.empty():
                found_pin, recovered_key = result_queue.get()

        except KeyboardInterrupt:
            print("\n[!] Ataque interrumpido por el usuario.")
            stop_event.set()
            for p in processes:
                p.terminate()

        elapsed_total = time.perf_counter() - t0
        sys.stdout.write("\n")

        if found_pin:
            keystream = generate_keystream(recovered_key, token.nonce_bytes, len(token.ciphertext_bytes))
            plaintext = xor_bytes(token.ciphertext_bytes, keystream).decode('utf-8', errors='replace')
            return {
                "success": True,
                "password": found_pin,
                "recovered_text": plaintext,
                "recovered_key_hex": recovered_key.hex(),
                "hashes_checked": counter.value,
                "elapsed_seconds": elapsed_total,
                "avg_hash_rate": counter.value / elapsed_total if elapsed_total > 0 else 0
            }
        else:
            return {
                "success": False,
                "password": None,
                "hashes_checked": counter.value,
                "elapsed_seconds": elapsed_total,
                "avg_hash_rate": counter.value / elapsed_total if elapsed_total > 0 else 0
            }

    def crack_dictionary(self, token_str: str, wordlist: List[str]) -> Dict[str, Any]:
        """
        Executes parallel multi-core dictionary attack (100% CPU load).
        """
        token = TokenStructure(token_str)
        if not token.is_password_protected:
            return self.break_unprotected(token_str)

        total_words = len(wordlist)
        chunk_size = math.ceil(total_words / self.num_workers)

        print(f"\n" + "="*70)
        print(f"[*] INICIANDO ATAQUE DE DICCIONARIO")
        print(f"[*] Esquema KDF: {token.kdf_type.upper()}")
        print(f"[*] Palabras en diccionario: {total_words:,}")
        print(f"[*] Nucleos de CPU asignados: {self.num_workers} (100% USO DE CPU)")
        print(f"="*70)

        stop_event = mp.Event()
        result_queue = mp.Queue()
        counter = mp.Value('i', 0)

        processes = []
        for i in range(self.num_workers):
            chunk = wordlist[i * chunk_size : (i + 1) * chunk_size]
            if not chunk:
                break
            p = mp.Process(
                target=_worker_dict_chunk,
                args=(
                    chunk, token.salt, token.enc_key, token.raw_key_package,
                    token.nonce_bytes, token.ciphertext_bytes, token.auth_tag,
                    stop_event, result_queue, counter, token.kdf_type
                )
            )
            p.daemon = True
            p.start()
            processes.append(p)

        t0 = time.perf_counter()
        found_pass = None
        recovered_key = None

        try:
            while any(p.is_alive() for p in processes):
                if stop_event.is_set():
                    break
                time.sleep(0.4)
                elapsed = time.perf_counter() - t0
                done = counter.value
                rate = done / elapsed if elapsed > 0 else 0
                pct = (done / total_words) * 100 if total_words > 0 else 0
                sys.stdout.write(
                    f"\r[CPU: 100%] Probados: {done:,}/{total_words:,} ({pct:.1f}%) "
                    f"| Velocidad: {rate:.1f} H/s | Tiempo: {elapsed:.1f}s"
                )
                sys.stdout.flush()

            for p in processes:
                p.join(timeout=1.0)

            if not result_queue.empty():
                found_pass, recovered_key = result_queue.get()

        except KeyboardInterrupt:
            stop_event.set()
            for p in processes:
                p.terminate()

        elapsed_total = time.perf_counter() - t0
        sys.stdout.write("\n")

        if found_pass:
            keystream = generate_keystream(recovered_key, token.nonce_bytes, len(token.ciphertext_bytes))
            plaintext = xor_bytes(token.ciphertext_bytes, keystream).decode('utf-8', errors='replace')
            return {
                "success": True,
                "password": found_pass,
                "recovered_text": plaintext,
                "recovered_key_hex": recovered_key.hex(),
                "hashes_checked": counter.value,
                "elapsed_seconds": elapsed_total,
                "avg_hash_rate": counter.value / elapsed_total if elapsed_total > 0 else 0
            }
        else:
            return {
                "success": False,
                "password": None,
                "hashes_checked": counter.value,
                "elapsed_seconds": elapsed_total,
                "avg_hash_rate": counter.value / elapsed_total if elapsed_total > 0 else 0
            }

    def run_cpu_stress_benchmark(self, duration_seconds: int = 3) -> Dict[str, Any]:
        """
        Stresses 100% of CPU cores executing both Scrypt and PBKDF2 (600k)
        and measures exact hardware throughput.
        """
        print(f"\n" + "="*70)
        print(f"[*] BENCHMARK MULTINUCLEO: COMPARATIVA SCRYPT VS PBKDF2 (100% CPU)")
        print(f"[*] Nucleos activos: {self.num_workers}")
        print(f"="*70)

        # 1. Scrypt benchmark
        print(f"\n[FASE 1] Evaluando Scrypt (Memory-Hard: N=16384, ~16 MB RAM por intento)...")
        stop_event = mp.Event()
        counter_scrypt = mp.Value('i', 0)
        procs_scrypt = []
        for _ in range(self.num_workers):
            p = mp.Process(target=_worker_benchmark_stress, args=("scrypt", SCRYPT_N, counter_scrypt, stop_event))
            p.daemon = True
            p.start()
            procs_scrypt.append(p)

        t0 = time.perf_counter()
        while time.perf_counter() - t0 < duration_seconds:
            elapsed = time.perf_counter() - t0
            done = counter_scrypt.value
            rate = done / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r[CPU 100% - SCRYPT MEMORY-HARD] Calculados: {done:,} | Tasa global: {rate:.2f} H/s")
            sys.stdout.flush()
            time.sleep(0.2)
        stop_event.set()
        for p in procs_scrypt:
            p.join(timeout=1.0)
        t_scrypt = time.perf_counter() - t0
        rate_scrypt = counter_scrypt.value / t_scrypt

        # 2. PBKDF2 600k benchmark
        print(f"\n\n[FASE 2] Evaluando PBKDF2 (OWASP 600,000 iteraciones)...")
        stop_event_pb = mp.Event()
        counter_pb = mp.Value('i', 0)
        procs_pb = []
        for _ in range(self.num_workers):
            p = mp.Process(target=_worker_benchmark_stress, args=("pbkdf2", PBKDF2_ROUNDS, counter_pb, stop_event_pb))
            p.daemon = True
            p.start()
            procs_pb.append(p)

        t0 = time.perf_counter()
        while time.perf_counter() - t0 < duration_seconds:
            elapsed = time.perf_counter() - t0
            done = counter_pb.value
            rate = done / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r[CPU 100% - PBKDF2 600K] Calculados: {done:,} | Tasa global: {rate:.2f} H/s")
            sys.stdout.flush()
            time.sleep(0.2)
        stop_event_pb.set()
        for p in procs_pb:
            p.join(timeout=1.0)
        t_pb = time.perf_counter() - t0
        rate_pb = counter_pb.value / t_pb

        sys.stdout.write("\n")
        print(f"\n[+] RESULTADOS COMPARATIVOS DE HARDWARE:")
        print(f"    - Scrypt (N=16384, Memory-Hard):     {rate_scrypt:.2f} H/s  (~{rate_scrypt/self.num_workers:.2f} H/s por nucleo)")
        print(f"    - PBKDF2 (600,000 iteraciones):      {rate_pb:.2f} H/s  (~{rate_pb/self.num_workers:.2f} H/s por nucleo)")

        return {
            "cores": self.num_workers,
            "scrypt_rate": rate_scrypt,
            "pbkdf2_rate": rate_pb
        }

# ---------------------------------------------------------------------------
# CLI & Standalone Interface
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="EncryptorX - Auditoria Criptografica y Rotura de Ofuscacion (100% CPU)"
    )
    parser.add_argument("--token", type=str, help="Token cifrado de EncryptorX a analizar o romper")
    parser.add_argument(
        "--mode",
        choices=["auto", "deobfuscate", "blind", "crack-pin", "crack-dict", "benchmark", "test-suite"],
        default="test-suite",
        help="Modo de operacion (por defecto: ejecuta test-suite completa)"
    )
    parser.add_argument("--workers", type=int, default=os.cpu_count(), help="Numero de procesos de CPU a utilizar (por defecto: todos)")
    parser.add_argument("--pin-digits", type=int, default=4, help="Longitud del PIN numerico a romper (default: 4)")
    parser.add_argument("--max-pins", type=int, default=None, help="Limite maximo de PINs a evaluar en pruebas")
    parser.add_argument("--wordlist", type=str, help="Ruta a archivo de diccionario para crack-dict")

    args = parser.parse_args()
    auditor = EncryptorXAuditor(num_workers=args.workers)

    if args.mode == "benchmark":
        auditor.run_cpu_stress_benchmark(duration_seconds=3)
        return

    if args.mode == "test-suite":
        run_complete_test_suite(auditor)
        return

    if not args.token:
        print("[ERROR] Debes proporcionar un token con --token para este modo.")
        sys.exit(1)

    if args.mode in ["auto", "deobfuscate", "blind"]:
        token_info = TokenStructure(args.token)
        print(f"[*] Analizando token...")
        print(f"    - Tipo: {'Multi-separador ($%&#)' if token_info.is_multi_separator else 'Mono-separador'}")
        print(f"    - Proteccion: {'CON CONTRASENA (' + token_info.kdf_type.upper() + ')' if token_info.is_password_protected else 'SIN CONTRASENA (Clave en texto)'}")

        if not token_info.is_password_protected:
            use_blind = (args.mode == "blind")
            result = auditor.break_unprotected(args.token, blind=use_blind)
            print(f"\n[+] VULNERABILIDAD CONFIRMADA: Clave recuperada al instante!")
            print(f"    - Metodo: {result['deobfuscation_type']}")
            print(f"    - Tiempo: {result['elapsed_ms']:.2f} ms")
            print(f"    - Clave AES/Keystream: {result['recovered_key_hex']}")
            print(f"    - Mensaje recuperado: \"{result['recovered_text']}\"")
        else:
            print(f"\n[!] El token esta blindado con {token_info.kdf_type.upper()}. Iniciando rotura multinucleo...")
            res = auditor.crack_pin(args.token, pin_length=args.pin_digits)
            if res["success"]:
                print(f"\n[+] EXITO: Contrasena encontrada: '{res['password']}'")
                print(f"    - Texto descifrado: \"{res['recovered_text']}\"")
                print(f"    - Tiempo: {res['elapsed_seconds']:.2f} s")
            else:
                print(f"\n[-] No se encontro el PIN en el rango especificado.")

    elif args.mode == "crack-pin":
        res = auditor.crack_pin(args.token, pin_length=args.pin_digits, max_pins=args.max_pins)
        if res["success"]:
            print(f"\n[+] PIN ENCONTRADO: '{res['password']}'")
            print(f"    - Texto descifrado: \"{res['recovered_text']}\"")
            print(f"    - Tiempo: {res['elapsed_seconds']:.2f} s")
        else:
            print(f"\n[-] PIN no encontrado.")

    elif args.mode == "crack-dict":
        if not args.wordlist or not os.path.exists(args.wordlist):
            print("[ERROR] Debes proporcionar un archivo existente con --wordlist.")
            sys.exit(1)
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        res = auditor.crack_dictionary(args.token, words)
        if res["success"]:
            print(f"\n[+] CONTRASENA ENCONTRADA: '{res['password']}'")
            print(f"    - Texto descifrado: \"{res['recovered_text']}\"")
        else:
            print(f"\n[-] Contrasena no encontrada en el diccionario.")

def run_complete_test_suite(auditor: EncryptorXAuditor):
    """
    Automated self-contained verification suite:
    1. Tests breaking unprotected tokens (standard & blind).
    2. Tests 100% CPU multi-core cracking of a Scrypt-protected PIN.
    3. Tests 100% CPU multi-core dictionary attack.
    4. Runs comparative hardware benchmark (Scrypt vs PBKDF2 600k).
    """
    import EncryptorX as enc

    print("\n" + "#"*70)
    print("### ENCRYPTORX - SUITE DE AUDITORIA SIMBOLICA Y MEMORY-HARD (SCRYPT) ###")
    print("#"*70)

    # 1. Test Unprotected Token
    print("\n" + "-"*70)
    print("[TEST 1/4] Prueba de Rotura de Token Simbolico SIN Contrasena")
    print("-" * 70)
    msg_secret = "Directiva confidencial: Plan Antigravity en curso."
    token_unprotected = enc.encrypt(msg_secret)
    print(f"Token simbolico generado: {token_unprotected[:60]}... ({len(token_unprotected)} caracteres)")
    assert "null" not in token_unprotected.lower(), "ERROR: Se encontro 'null' en el token"

    # Standard deobfuscation
    res1 = auditor.break_unprotected(token_unprotected, blind=False)
    print(f"[+] Rotura directa completada en {res1['elapsed_ms']:.2f} ms")
    print(f"    - Clave recuperada: {res1['recovered_key_hex']}")
    print(f"    - Texto recuperado: \"{res1['recovered_text']}\"")
    assert res1['recovered_text'] == msg_secret, "Fallo en recuperacion de texto"

    # Blind heuristic deobfuscation
    res1_blind = auditor.break_unprotected(token_unprotected, blind=True)
    print(f"[+] Rotura CIEGA (heuristica de simbolos) en {res1_blind['elapsed_ms']:.2f} ms")
    assert res1_blind['recovered_text'] == msg_secret, "Fallo en rotura ciega"
    print(f"    - Resultado: 100% EXITOSO. Token desofuscado.")

    # 2. Test Multi-Core PIN Cracking with Scrypt (100% CPU)
    print("\n" + "-"*70)
    print("[TEST 2/4] Prueba de Fuerza Bruta Multiproceso de PIN con SCRYPT (100% CPU)")
    print("-" * 70)
    target_pin = "0042"
    msg_pin = "Datos protegidos con Scrypt Memory-Hard."
    token_pin = enc.encrypt(msg_pin, password=target_pin, use_scrypt=True)
    print(f"Token protegido con Scrypt y PIN '{target_pin}' generado.")
    print(f"Lanzando ataque paralelo en {auditor.num_workers} nucleos...")

    res2 = auditor.crack_pin(token_pin, pin_length=4, max_pins=200)
    print(f"[+] Resultado PIN: {res2}")
    assert res2["success"] is True, "Fallo en ataque de PIN Scrypt"
    assert res2["password"] == target_pin, f"PIN incorrecto: {res2['password']}"
    assert res2["recovered_text"] == msg_pin, "Texto descifrado incorrecto"
    print(f"[+] PIN '{res2['password']}' roto con exito en {res2['elapsed_seconds']:.2f} s ({res2['avg_hash_rate']:.1f} H/s con Scrypt 16MB).")

    # 3. Test Multi-Core Dictionary Cracking (100% CPU)
    print("\n" + "-"*70)
    print("[TEST 3/4] Prueba de Ataque de Diccionario Multiproceso (100% CPU)")
    print("-" * 70)
    dict_pass = "shadowhawk"
    msg_dict = "Credenciales de root para cluster AWS."
    token_dict = enc.encrypt(msg_dict, password=dict_pass, use_scrypt=True)
    test_wordlist = ["admin", "123456", "password", "dragon", "master", "shadowhawk", "qwerty"]
    print(f"Token protegido con contrasena de diccionario generado.")

    res3 = auditor.crack_dictionary(token_dict, test_wordlist)
    assert res3["success"] is True, "Fallo en ataque de diccionario"
    assert res3["password"] == dict_pass, "Contrasena incorrecta"
    assert res3["recovered_text"] == msg_dict, "Texto descifrado incorrecto"
    print(f"[+] Contrasena '{res3['password']}' recuperada con exito del diccionario!")

    # 4. Multi-Core Benchmark
    print("\n" + "-"*70)
    print("[TEST 4/4] Benchmark Comparativo de Hardware (Scrypt vs PBKDF2)")
    print("-" * 70)
    bench_res = auditor.run_cpu_stress_benchmark(duration_seconds=2)

    print("\n" + "="*70)
    print("[***] AUDITORIA FINALIZADA: 100% DE PRUEBAS COMPLETADAS CON EXITO [***]")
    print("="*70)

if __name__ == "__main__":
    # Multi-processing bootstrap for Windows
    mp.freeze_support()
    main()
