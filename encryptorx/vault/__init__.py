"""
Vault module for EncryptorX.
Multi-file directory container encryption (.vault) with MFA (Password + Keyfile) and compression.
"""

from .vault import (
    create_vault,
    extract_vault,
    inspect_vault,
    generate_keyfile,
    VaultArchive,
)

__all__ = [
    "create_vault",
    "extract_vault",
    "inspect_vault",
    "generate_keyfile",
    "VaultArchive",
]
