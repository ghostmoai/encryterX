"""
ChaCha20 and Poly1305 Authenticated Encryption with Associated Data (AEAD).
Pure Python implementation compliant with RFC 8439.
Zero external dependencies.
"""
from __future__ import annotations

import struct
from typing import Tuple


def _rotl32(v: int, c: int) -> int:
    """Rotate left a 32-bit integer."""
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    """ChaCha quarter round operation on state vector x."""
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 7)


class ChaCha20:
    """
    ChaCha20 stream cipher engine.
    Supports RFC 8439 96-bit nonce and 32-bit counter.
    """

    SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        if len(key) != 32:
            raise ValueError("ChaCha20 key must be exactly 32 bytes (256 bits).")
        if len(nonce) != 12:
            raise ValueError("ChaCha20 nonce must be exactly 12 bytes (96 bits).")
        self.key = key
        self.nonce = nonce
        self.counter = counter & 0xFFFFFFFF

    def _block(self, counter: int) -> bytes:
        """Generate a single 64-byte ChaCha20 keystream block."""
        key_words = list(struct.unpack("<8I", self.key))
        nonce_words = list(struct.unpack("<3I", self.nonce))

        state = self.SIGMA + key_words + [counter] + nonce_words
        working = list(state)

        for _ in range(10):
            # Column rounds
            _quarter_round(working, 0, 4, 8, 12)
            _quarter_round(working, 1, 5, 9, 13)
            _quarter_round(working, 2, 6, 10, 14)
            _quarter_round(working, 3, 7, 11, 15)
            # Diagonal rounds
            _quarter_round(working, 0, 5, 10, 15)
            _quarter_round(working, 1, 6, 11, 12)
            _quarter_round(working, 2, 7, 8, 13)
            _quarter_round(working, 3, 4, 9, 14)

        for i in range(16):
            working[i] = (working[i] + state[i]) & 0xFFFFFFFF

        return struct.pack("<16I", *working)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt or decrypt arbitrary-length byte sequences."""
        out = bytearray()
        ctr = self.counter
        for i in range(0, len(data), 64):
            chunk = data[i:i + 64]
            ks = self._block(ctr)
            out.extend(b ^ k for b, k in zip(chunk, ks[:len(chunk)]))
            ctr = (ctr + 1) & 0xFFFFFFFF
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)


class Poly1305:
    """
    Poly1305 one-time authenticator.
    Computes a 128-bit MAC using a 32-byte one-time key over prime 2^130 - 5.
    """

    PRIME = (1 << 130) - 5

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Poly1305 key must be exactly 32 bytes.")
        r_raw = key[:16]
        s_raw = key[16:]

        # Clamp r
        r_int = int.from_bytes(r_raw, "little")
        r_clamped = r_int & 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.r = r_clamped
        self.s = int.from_bytes(s_raw, "little")
        self.acc = 0

    def update(self, data: bytes) -> None:
        """Process data chunks of 16 bytes."""
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            n = int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))
            self.acc = ((self.acc + n) * self.r) % self.PRIME

    def digest(self) -> bytes:
        """Compute the final 16-byte authentication tag."""
        tag_int = (self.acc + self.s) & ((1 << 128) - 1)
        return tag_int.to_bytes(16, "little")


def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes = b""
) -> Tuple[bytes, bytes]:
    """
    RFC 8439 Authenticated Encryption with Associated Data (AEAD).

    Args:
        key: 32-byte secret key.
        nonce: 12-byte initialization vector.
        plaintext: Data to encrypt.
        associated_data: Optional authenticated but unencrypted data.

    Returns:
        Tuple of (ciphertext, 16-byte authentication_tag).
    """
    # 1. Generate one-time Poly1305 key using counter 0
    engine = ChaCha20(key, nonce, counter=0)
    poly_key = engine._block(0)[:32]

    # 2. Encrypt plaintext using counter 1
    cipher_engine = ChaCha20(key, nonce, counter=1)
    ciphertext = cipher_engine.encrypt(plaintext)

    # 3. Construct authentication buffer
    poly = Poly1305(poly_key)
    if associated_data:
        poly.update(associated_data)
        if len(associated_data) % 16 != 0:
            poly.update(b"\x00" * (16 - (len(associated_data) % 16)))

    if ciphertext:
        poly.update(ciphertext)
        if len(ciphertext) % 16 != 0:
            poly.update(b"\x00" * (16 - (len(ciphertext) % 16)))

    lengths = struct.pack("<QQ", len(associated_data), len(ciphertext))
    poly.update(lengths)
    tag = poly.digest()

    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: bytes = b""
) -> bytes:
    """
    RFC 8439 Authenticated Decryption with Associated Data (AEAD).

    Raises:
        ValueError: If the authentication tag is invalid.
    """
    if len(tag) != 16:
        raise ValueError("Invalid authentication tag length: expected 16 bytes.")

    engine = ChaCha20(key, nonce, counter=0)
    poly_key = engine._block(0)[:32]

    poly = Poly1305(poly_key)
    if associated_data:
        poly.update(associated_data)
        if len(associated_data) % 16 != 0:
            poly.update(b"\x00" * (16 - (len(associated_data) % 16)))

    if ciphertext:
        poly.update(ciphertext)
        if len(ciphertext) % 16 != 0:
            poly.update(b"\x00" * (16 - (len(ciphertext) % 16)))

    lengths = struct.pack("<QQ", len(associated_data), len(ciphertext))
    poly.update(lengths)
    expected_tag = poly.digest()

    # Constant-time comparison
    diff = 0
    for a, b in zip(tag, expected_tag):
        diff |= a ^ b

    if diff != 0:
        raise ValueError("ChaCha20-Poly1305 authentication failed: tag mismatch.")

    cipher_engine = ChaCha20(key, nonce, counter=1)
    return cipher_engine.decrypt(ciphertext)
