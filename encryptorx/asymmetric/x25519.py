"""
X25519 Elliptic Curve Diffie-Hellman (ECDH) Key Exchange.
Pure Python implementation compliant with RFC 7748 (Curve25519).
Uses the Montgomery ladder in constant-time coordinates.
Zero external dependencies.
"""
from __future__ import annotations

import os
from typing import Tuple

P = 2**255 - 19
A24 = 121665  # (486662 - 2) // 4


def _inv(x: int) -> int:
    """Modular inverse modulo 2^255 - 19 using Fermat's Little Theorem."""
    return pow(x, P - 2, P)


def _cswap(swap: int, x_2: int, x_3: int) -> Tuple[int, int]:
    """Conditional swap in constant-time logic."""
    dummy = swap * (x_2 - x_3)
    x_2 -= dummy
    x_3 += dummy
    return x_2, x_3


def x25519(k: bytes, u_bytes: bytes) -> bytes:
    """
    RFC 7748 X25519 scalar multiplication: R = k * U.

    Args:
        k: 32-byte scalar (private key).
        u_bytes: 32-byte u-coordinate (public key or base point).

    Returns:
        32-byte resulting u-coordinate.
    """
    # 1. Clamp scalar as specified in RFC 7748
    k_bytes = bytearray(k)
    k_bytes[0] &= 248
    k_bytes[31] &= 127
    k_bytes[31] |= 64
    k_int = int.from_bytes(k_bytes, "little")

    # 2. Decode u-coordinate (mask MSB)
    u_int = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)

    x_1 = u_int
    x_2 = 1
    z_2 = 0
    x_3 = u_int
    z_3 = 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t

        a = (x_2 + z_2) % P
        aa = (a * a) % P
        b = (x_2 - z_2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x_3 + z_3) % P
        d = (x_3 - z_3) % P
        da = (d * a) % P
        cb = (c * b) % P

        x_3 = ((da + cb) ** 2) % P
        z_3 = (x_1 * ((da - cb) ** 2)) % P
        x_2 = (aa * bb) % P
        z_2 = (e * (aa + A24 * e)) % P

    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)

    res = (x_2 * _inv(z_2)) % P
    return res.to_bytes(32, "little")


# Base point for Curve25519 (u = 9)
BASE_POINT = (9).to_bytes(32, "little")


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an X25519 private key (32 bytes) and public key (32 bytes).

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = os.urandom(32)
    public_key = x25519(private_key, BASE_POINT)
    return private_key, public_key


def derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """
    Derive a 256-bit Diffie-Hellman shared secret between private key and peer public key.

    Returns:
        32-byte shared secret point.
    """
    shared = x25519(private_key, peer_public_key)
    # Check for low-order points (RFC 7748 Section 6.1)
    if shared == b"\x00" * 32:
        raise ValueError("Low-order point rejected in key agreement.")
    return shared
