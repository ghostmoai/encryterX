"""
encryptorx
==========

A Python library for text and file encryption/decryption, plus Base64 utilities.

Quick start
-----------
    import encryptorx

    # Custom stream-cipher encryption (key stored locally)
    cypher = encryptorx.encrypt("Hello, world!")
    plain  = encryptorx.decrypt(cypher)

    # Base64
    encoded = encryptorx.b64_encode("Hello")
    decoded = encryptorx.b64_decode(encoded)

    # File encryption
    encryptorx.encrypt_file("secret.txt")          # writes secret.txt.enc
    encryptorx.decrypt_file("secret.txt.enc")      # writes secret.txt (or .dec variant)

    # Using a custom key
    import os
    my_key = os.urandom(32)
    enc = encryptorx.encrypt("Hi", key=my_key)
    dec = encryptorx.decrypt(enc, key=my_key)

© 2025 ghostmoai. All rights reserved.
"""

from .crypto import (
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
    generate_key,
    generate_secure_password,
    load_key,
    save_key,
)
from .base64_utils import (
    b64_encode,
    b64_decode,
    b64_encode_bytes,
    b64_decode_bytes,
    is_valid_base64,
)
from .stego import (
    hide_text,
    extract_text,
    hide_file,
    extract_file,
    get_image_capacity,
    calculate_metrics,
    StegoEngine,
    StegoError,
    CapacityError,
    AuthenticationError,
    CorruptDataError,
)
from . import ciphers
from . import asymmetric
from . import secret_sharing
from . import vault
from . import entropy

from .ciphers import (
    ChaCha20,
    Poly1305,
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
    AES256,
    aes256_ctr_encrypt,
    aes256_ctr_decrypt,
    aes256_gcm_encrypt,
    aes256_gcm_decrypt,
)
from .asymmetric import (
    x25519,
    generate_x25519_keypair,
    derive_shared_secret,
    generate_signing_keypair,
    ed25519_sign,
    ed25519_verify,
)
from .secret_sharing import (
    ShamirSecretSharing,
    split_secret,
    combine_shares,
)
from .vault import (
    create_vault,
    extract_vault,
    inspect_vault,
    generate_keyfile,
    VaultArchive,
)
from .entropy import (
    EntropyAuditor,
    audit_randomness,
)

__version__ = "3.2.0"
__author__  = "ghostmoai"
__all__ = [
    # Crypto
    "encrypt",
    "decrypt",
    "encrypt_file",
    "decrypt_file",
    "generate_key",
    "generate_secure_password",
    "load_key",
    "save_key",
    # Base64
    "b64_encode",
    "b64_decode",
    "b64_encode_bytes",
    "b64_decode_bytes",
    "is_valid_base64",
    # Steganography
    "stego",
    "hide_text",
    "extract_text",
    "hide_file",
    "extract_file",
    "get_image_capacity",
    "calculate_metrics",
    "StegoEngine",
    "StegoError",
    "CapacityError",
    "AuthenticationError",
    "CorruptDataError",
    # Submodules
    "ciphers",
    "asymmetric",
    "secret_sharing",
    "vault",
    "entropy",
    # Ciphers
    "ChaCha20",
    "Poly1305",
    "chacha20_poly1305_encrypt",
    "chacha20_poly1305_decrypt",
    "AES256",
    "aes256_ctr_encrypt",
    "aes256_ctr_decrypt",
    "aes256_gcm_encrypt",
    "aes256_gcm_decrypt",
    # Asymmetric
    "x25519",
    "generate_x25519_keypair",
    "derive_shared_secret",
    "generate_signing_keypair",
    "ed25519_sign",
    "ed25519_verify",
    # Secret Sharing
    "ShamirSecretSharing",
    "split_secret",
    "combine_shares",
    # Vault
    "create_vault",
    "extract_vault",
    "inspect_vault",
    "generate_keyfile",
    "VaultArchive",
    # Entropy
    "EntropyAuditor",
    "audit_randomness",
]

