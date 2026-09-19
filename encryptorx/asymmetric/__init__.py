"""
Asymmetric cryptography module for EncryptorX.
Provides X25519 ECDH key exchange (RFC 7748) and Ed25519 digital signatures (RFC 8032).
"""

from .x25519 import (
    x25519,
    generate_keypair as generate_x25519_keypair,
    derive_shared_secret,
)

from .ed25519 import (
    generate_signing_keypair,
    ed25519_sign,
    ed25519_verify,
)

__all__ = [
    "x25519",
    "generate_x25519_keypair",
    "derive_shared_secret",
    "generate_signing_keypair",
    "ed25519_sign",
    "ed25519_verify",
]
