"""
Shamir's Secret Sharing Scheme (SSSS).
Threshold Cryptography (k, n) over Galois Field GF(256).
Zero external dependencies.
"""
from __future__ import annotations

import os
from typing import List, Tuple

# Irreducible polynomial for AES/Rijndael: x^8 + x^4 + x^3 + x + 1 (0x11B)
# Generator 3 is primitive with period 255
def _mul_poly_step(val: int) -> int:
    res = 0
    b = 3
    a = val
    while b > 0:
        if b & 1:
            res ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return res

EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256

_curr = 1
for _i in range(255):
    EXP_TABLE[_i] = _curr
    EXP_TABLE[_i + 255] = _curr
    LOG_TABLE[_curr] = _i
    _curr = _mul_poly_step(_curr)


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256).")
    if a == 0:
        return 0
    return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255]


def _eval_polynomial(coefficients: List[int], x_val: int) -> int:
    """Evaluate polynomial over GF(256) using Horner's method."""
    result = 0
    for coef in reversed(coefficients):
        result = _gf_mul(result, x_val) ^ coef
    return result


class ShamirSecretSharing:
    """
    Shamir's Threshold Secret Sharing Engine.
    Allows splitting any secret bytes into n shares, such that any k shares
    can perfectly recover the secret, while k-1 shares provide zero information.
    """

    @staticmethod
    def split(secret: bytes, k: int, n: int) -> List[Tuple[int, bytes]]:
        """
        Split a secret into n shares with threshold k.

        Args:
            secret: Arbitrary byte string.
            k: Minimum number of shares required to reconstruct (threshold).
            n: Total number of shares to generate.

        Returns:
            List of (x, share_bytes) pairs, where x in [1, n].
        """
        if k < 2:
            raise ValueError("Threshold k must be at least 2.")
        if n < k:
            raise ValueError("Total shares n must be greater than or equal to threshold k.")
        if n > 255:
            raise ValueError("Total shares n cannot exceed 255 in GF(256).")
        if not secret:
            raise ValueError("Secret cannot be empty.")

        shares = [bytearray() for _ in range(n)]

        for byte_val in secret:
            # Generate random coefficients: a_0 = byte_val, a_1..a_{k-1} random
            coeffs = [byte_val] + list(os.urandom(k - 1))
            for x_idx in range(1, n + 1):
                y = _eval_polynomial(coeffs, x_idx)
                shares[x_idx - 1].append(y)

        return [(idx + 1, bytes(shares[idx])) for idx in range(n)]

    @staticmethod
    def combine(shares: List[Tuple[int, bytes]]) -> bytes:
        """
        Reconstruct a secret from at least k shares using Lagrange interpolation.

        Args:
            shares: List of (x, share_bytes) pairs.

        Returns:
            Reconstructed secret bytes.
        """
        if not shares:
            raise ValueError("At least one share is required.")

        k = len(shares)
        share_len = len(shares[0][1])

        # Verify all shares have identical lengths and unique x-coordinates
        x_set = set()
        for x_val, s_bytes in shares:
            if x_val in x_set:
                raise ValueError(f"Duplicate share index {x_val}.")
            x_set.add(x_val)
            if len(s_bytes) != share_len:
                raise ValueError("Share lengths do not match.")

        secret = bytearray(share_len)

        for byte_idx in range(share_len):
            secret_byte = 0
            for j in range(k):
                x_j, y_j_bytes = shares[j]
                y_j = y_j_bytes[byte_idx]

                # Compute Lagrange basis polynomial l_j(0) = prod_{m != j} (x_m / (x_m ^ x_j))
                numerator = 1
                denominator = 1
                for m in range(k):
                    if m == j:
                        continue
                    x_m, _ = shares[m]
                    numerator = _gf_mul(numerator, x_m)
                    denominator = _gf_mul(denominator, x_m ^ x_j)

                l_j_0 = _gf_div(numerator, denominator)
                term = _gf_mul(y_j, l_j_0)
                secret_byte ^= term

            secret[byte_idx] = secret_byte

        return bytes(secret)


def split_secret(secret: bytes | str, k: int, n: int) -> List[str]:
    """
    Convenience function: Splits a secret and returns human-readable formatted share strings.
    Format: '<index>-<hex_data>'
    """
    data = secret.encode("utf-8") if isinstance(secret, str) else secret
    raw_shares = ShamirSecretSharing.split(data, k, n)
    return [f"{idx}-{payload.hex()}" for idx, payload in raw_shares]


def combine_shares(share_strings: List[str]) -> bytes:
    """
    Convenience function: Combines human-readable share strings into the original secret bytes.
    """
    parsed = []
    for s in share_strings:
        parts = s.strip().split("-", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid share format: '{s}'. Expected '<index>-<hex>'.")
        idx = int(parts[0])
        data = bytes.fromhex(parts[1])
        parsed.append((idx, data))
    return ShamirSecretSharing.combine(parsed)
