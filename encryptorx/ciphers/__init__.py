"""
Symmetric ciphers module for EncryptorX.
Provides ChaCha20-Poly1305 (RFC 8439) and AES-256 (CTR / GCM) in pure Python.
"""

from .chacha20 import (
    ChaCha20,
    Poly1305,
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
)

from .aes import (
    AES256,
    aes256_ctr_encrypt,
    aes256_ctr_decrypt,
    aes256_gcm_encrypt,
    aes256_gcm_decrypt,
)

__all__ = [
    "ChaCha20",
    "Poly1305",
    "chacha20_poly1305_encrypt",
    "chacha20_poly1305_decrypt",
    "AES256",
    "aes256_ctr_encrypt",
    "aes256_ctr_decrypt",
    "aes256_gcm_encrypt",
    "aes256_gcm_decrypt",
]
