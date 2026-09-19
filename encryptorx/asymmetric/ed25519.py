"""
Ed25519 Digital Signature Algorithm (EdDSA).
Pure Python implementation compliant with RFC 8032.
Zero external dependencies.
"""
from __future__ import annotations

import os
import hashlib
from typing import Tuple

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


D = (-121665 * _inv(121666)) % P
I = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, sign: int) -> int:
    if y >= P:
        return 0
    x2 = ((y * y - 1) * _inv(D * y * y + 1)) % P
    if x2 == 0:
        return 0 if sign == 0 else P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * I) % P
    if (x * x - x2) % P != 0:
        return 0
    if (x & 1) != sign:
        x = P - x
    return x


# Base point coordinates
BY = (4 * _inv(5)) % P
BX = _recover_x(BY, 0)
B = (BX, BY, 1, (BX * BY) % P)  # Extended coordinates (X, Y, Z, T)


def _ed_add(p: Tuple[int, int, int, int], q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """Point addition on Edwards curve in extended coordinates."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * D) % P
    d = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return (e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P


def _ed_double(p: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """Point doubling on Edwards curve in extended coordinates."""
    x1, y1, z1, _ = p
    a = (x1 * x1) % P
    b = (y1 * y1) % P
    c = (2 * z1 * z1) % P
    d = (-a) % P
    e = ((x1 + y1) ** 2 - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P


def _ed_mul(p: Tuple[int, int, int, int], s: int) -> Tuple[int, int, int, int]:
    """Scalar multiplication: s * P."""
    res = (0, 1, 1, 0)  # Identity point
    curr = p
    while s > 0:
        if s & 1:
            res = _ed_add(res, curr)
        curr = _ed_double(curr)
        s >>= 1
    return res


def _encode_point(p: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    inv_z = _inv(z)
    aff_x = (x * inv_z) % P
    aff_y = (y * inv_z) % P
    val = aff_y | ((aff_x & 1) << 255)
    return val.to_bytes(32, "little")


def _decode_point(data: bytes) -> Tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    val = int.from_bytes(data, "little")
    sign = val >> 255
    y = val & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x == 0 and sign != 0:
        return None
    return x, y, 1, (x * y) % P


def generate_signing_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an Ed25519 signing keypair.

    Returns:
        Tuple of (private_seed: 32 bytes, public_key: 32 bytes).
    """
    seed = os.urandom(32)
    h = hashlib.sha512(seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 63
    a_bytes[31] |= 64
    s = int.from_bytes(a_bytes, "little")

    pub_point = _ed_mul(B, s)
    public_key = _encode_point(pub_point)
    return seed, public_key


def ed25519_sign(secret_seed: bytes, message: bytes) -> bytes:
    """
    Sign a message using an Ed25519 private seed (32 bytes).

    Returns:
        64-byte Ed25519 digital signature (R || S).
    """
    if len(secret_seed) != 32:
        raise ValueError("Secret seed must be 32 bytes.")

    h = hashlib.sha512(secret_seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 63
    a_bytes[31] |= 64
    s_a = int.from_bytes(a_bytes, "little")
    prefix = h[32:]

    # Compute public key
    a_point = _ed_mul(B, s_a)
    public_key = _encode_point(a_point)

    # r = SHA-512(prefix || message) mod L
    r_hash = hashlib.sha512(prefix + message).digest()
    r = int.from_bytes(r_hash, "little") % L

    # R = r * B
    r_point = _ed_mul(B, r)
    r_bytes = _encode_point(r_point)

    # k = SHA-512(R || public_key || message) mod L
    k_hash = hashlib.sha512(r_bytes + public_key + message).digest()
    k = int.from_bytes(k_hash, "little") % L

    # S = (r + k * s_a) mod L
    s = (r + k * s_a) % L
    s_bytes = s.to_bytes(32, "little")

    return r_bytes + s_bytes


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an Ed25519 digital signature.

    Returns:
        True if valid, False otherwise.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False

    r_bytes = signature[:32]
    s_bytes = signature[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False

    a_point = _decode_point(public_key)
    if a_point is None:
        return False

    r_point = _decode_point(r_bytes)
    if r_point is None:
        return False

    # k = SHA-512(R || public_key || message) mod L
    k_hash = hashlib.sha512(r_bytes + public_key + message).digest()
    k = int.from_bytes(k_hash, "little") % L

    # Check: s * B == R + k * A
    sb_point = _ed_mul(B, s)
    ka_point = _ed_mul(a_point, k)
    expected_point = _ed_add(r_point, ka_point)

    return _encode_point(sb_point) == _encode_point(expected_point)
