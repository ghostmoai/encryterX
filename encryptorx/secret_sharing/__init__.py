"""
Shamir's Secret Sharing module for EncryptorX.
Threshold cryptography (k, n) over Galois Field GF(256).
"""

from .shamir import (
    ShamirSecretSharing,
    split_secret,
    combine_shares,
)

__all__ = [
    "ShamirSecretSharing",
    "split_secret",
    "combine_shares",
]
