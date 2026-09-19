"""
Advanced Encryption Standard (AES-256 / Rijndael).
Pure Python implementation compliant with FIPS PUB 197 and NIST SP 800-38D (GCM).
Zero external dependencies.
"""
from __future__ import annotations

import os
from typing import Tuple, List

# ---------------------------------------------------------------------------
# S-Box & Inverted S-Box Lookups
# ---------------------------------------------------------------------------
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _mul(a: int, b: int) -> int:
    res = 0
    while b > 0:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


class AES256:
    """Pure Python AES-256 implementation."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key.")
        self.round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """Expand 256-bit key into 15 round keys of 16 bytes each."""
        w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
        for i in range(8, 60):
            temp = list(w[i - 1])
            if i % 8 == 0:
                # RotWord & SubWord & Rcon
                temp = temp[1:] + temp[:1]
                temp = [S_BOX[b] for b in temp]
                temp[0] ^= RCON[i // 8]
            elif i % 8 == 4:
                # SubWord
                temp = [S_BOX[b] for b in temp]
            w.append([a ^ b for a, b in zip(w[i - 8], temp)])

        round_keys = []
        for r in range(15):
            rk = []
            for col in range(4):
                rk.extend(w[r * 4 + col])
            round_keys.append(rk)
        return round_keys

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block."""
        if len(block) != 16:
            raise ValueError("Block must be exactly 16 bytes.")
        state = list(block)

        # AddRoundKey (Round 0)
        state = [s ^ k for s, k in zip(state, self.round_keys[0])]

        for r in range(1, 14):
            # SubBytes
            state = [S_BOX[b] for b in state]
            # ShiftRows
            state = [
                state[0], state[5], state[10], state[15],
                state[4], state[9], state[14], state[3],
                state[8], state[13], state[2], state[7],
                state[12], state[1], state[6], state[11]
            ]
            # MixColumns
            new_state = [0] * 16
            for c in range(4):
                idx = c * 4
                s0, s1, s2, s3 = state[idx], state[idx + 1], state[idx + 2], state[idx + 3]
                new_state[idx] = _mul(s0, 2) ^ _mul(s1, 3) ^ s2 ^ s3
                new_state[idx + 1] = s0 ^ _mul(s1, 2) ^ _mul(s2, 3) ^ s3
                new_state[idx + 2] = s0 ^ s1 ^ _mul(s2, 2) ^ _mul(s3, 3)
                new_state[idx + 3] = _mul(s0, 3) ^ s1 ^ s2 ^ _mul(s3, 2)
            state = new_state
            # AddRoundKey
            state = [s ^ k for s, k in zip(state, self.round_keys[r])]

        # Final Round (No MixColumns)
        state = [S_BOX[b] for b in state]
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]
        state = [s ^ k for s, k in zip(state, self.round_keys[14])]
        return bytes(state)


# ---------------------------------------------------------------------------
# Modes of Operation: CTR & GCM
# ---------------------------------------------------------------------------

def aes256_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    AES-256 in Counter Mode (CTR).
    Nonce must be 12 to 16 bytes.
    """
    if len(nonce) < 12 or len(nonce) > 16:
        raise ValueError("Nonce must be between 12 and 16 bytes.")
    base_counter = nonce.ljust(16, b"\x00")
    initial_iv = int.from_bytes(base_counter, "big")

    cipher = AES256(key)
    out = bytearray()
    ctr = initial_iv

    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        iv_bytes = (ctr & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(16, "big")
        keystream = cipher.encrypt_block(iv_bytes)
        out.extend(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
        ctr += 1

    return bytes(out)


def aes256_ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return aes256_ctr_encrypt(key, nonce, ciphertext)


# ---------------------------------------------------------------------------
# Galois/Counter Mode (GHASH over GF(2^128))
# ---------------------------------------------------------------------------

def _gf128_mul(x: int, y: int) -> int:
    """Multiplication in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1."""
    R = 0xE1000000000000000000000000000000
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def _ghash(h_int: int, data: bytes) -> bytes:
    y = 0
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16].ljust(16, b"\x00")
        block_int = int.from_bytes(chunk, "big")
        y = _gf128_mul(y ^ block_int, h_int)
    return y.to_bytes(16, "big")


def aes256_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes = b""
) -> Tuple[bytes, bytes]:
    """
    AES-256 Galois/Counter Mode (GCM) AEAD encryption.

    Args:
        key: 32-byte AES key.
        nonce: 12-byte initialization vector.
        plaintext: Plaintext data.
        associated_data: Unencrypted authenticated data.

    Returns:
        Tuple of (ciphertext, 16-byte authentication_tag).
    """
    if len(nonce) != 12:
        raise ValueError("GCM recommended nonce length is 12 bytes.")
    cipher = AES256(key)

    # Hash subkey H = AES_K(0^128)
    h_bytes = cipher.encrypt_block(b"\x00" * 16)
    h_int = int.from_bytes(h_bytes, "big")

    # Initial counter block J0 = Nonce || 0x00000001
    j0 = nonce + b"\x00\x00\x00\x01"

    # Encrypt plaintext starting from counter block J0 + 1
    j_int = int.from_bytes(j0, "big")
    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr_block = ((j_int + 1 + (i // 16)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(16, "big")
        ks = cipher.encrypt_block(ctr_block)
        ciphertext.extend(b ^ k for b, k in zip(chunk, ks[:len(chunk)]))

    ciphertext_bytes = bytes(ciphertext)

    # Compute GHASH over AAD || pad || Ciphertext || pad || len(AAD) || len(C)
    auth_buf = bytearray()
    auth_buf.extend(associated_data)
    if len(associated_data) % 16 != 0:
        auth_buf.extend(b"\x00" * (16 - (len(associated_data) % 16)))

    auth_buf.extend(ciphertext_bytes)
    if len(ciphertext_bytes) % 16 != 0:
        auth_buf.extend(b"\x00" * (16 - (len(ciphertext_bytes) % 16)))

    len_block = (len(associated_data) * 8).to_bytes(8, "big") + (len(ciphertext_bytes) * 8).to_bytes(8, "big")
    auth_buf.extend(len_block)

    s = _ghash(h_int, bytes(auth_buf))
    # Tag = GHASH ^ AES_K(J0)
    enc_j0 = cipher.encrypt_block(j0)
    tag = bytes(a ^ b for a, b in zip(s, enc_j0))

    return ciphertext_bytes, tag


def aes256_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: bytes = b""
) -> bytes:
    """
    AES-256 Galois/Counter Mode (GCM) AEAD decryption.

    Raises:
        ValueError: If authentication tag fails verification.
    """
    if len(nonce) != 12:
        raise ValueError("GCM recommended nonce length is 12 bytes.")
    if len(tag) != 16:
        raise ValueError("GCM tag must be 16 bytes.")

    cipher = AES256(key)
    h_bytes = cipher.encrypt_block(b"\x00" * 16)
    h_int = int.from_bytes(h_bytes, "big")

    j0 = nonce + b"\x00\x00\x00\x01"

    auth_buf = bytearray()
    auth_buf.extend(associated_data)
    if len(associated_data) % 16 != 0:
        auth_buf.extend(b"\x00" * (16 - (len(associated_data) % 16)))

    auth_buf.extend(ciphertext)
    if len(ciphertext) % 16 != 0:
        auth_buf.extend(b"\x00" * (16 - (len(ciphertext) % 16)))

    len_block = (len(associated_data) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    auth_buf.extend(len_block)

    s = _ghash(h_int, bytes(auth_buf))
    enc_j0 = cipher.encrypt_block(j0)
    expected_tag = bytes(a ^ b for a, b in zip(s, enc_j0))

    diff = 0
    for a, b in zip(tag, expected_tag):
        diff |= a ^ b

    if diff != 0:
        raise ValueError("AES-256-GCM authentication failed: tag mismatch.")

    # Decrypt
    j_int = int.from_bytes(j0, "big")
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr_block = ((j_int + 1 + (i // 16)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(16, "big")
        ks = cipher.encrypt_block(ctr_block)
        plaintext.extend(b ^ k for b, k in zip(chunk, ks[:len(chunk)]))

    return bytes(plaintext)
