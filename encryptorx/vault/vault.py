"""
EncryptorVault: Cryptographic Container System (.vault).
Packages and encrypts entire directories or multi-file archives with metadata,
compression, and Multi-Factor Authentication (Master Password + 256-bit Keyfile).
Zero external dependencies.
"""
from __future__ import annotations

import os
import io
import json
import zlib
import struct
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List

from ..ciphers.chacha20 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from ..ciphers.aes import aes256_gcm_encrypt, aes256_gcm_decrypt

VAULT_MAGIC = b"EXVAULT1"
KEYFILE_SIZE = 32
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1


def generate_keyfile(destination_path: str | Path) -> Path:
    """
    Generate a 256-bit cryptographically secure keyfile for Multi-Factor vault authentication.
    """
    dest = Path(destination_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    key_bytes = os.urandom(KEYFILE_SIZE)
    dest.write_bytes(key_bytes)
    return dest


def _read_keyfile(path: Optional[str | Path]) -> bytes:
    if not path:
        return b""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Keyfile not found: {p}")
    data = p.read_bytes()
    if len(data) < KEYFILE_SIZE:
        raise ValueError(f"Keyfile must be at least {KEYFILE_SIZE} bytes.")
    return hashlib.sha256(data).digest()


def _derive_vault_key(
    password: Optional[str],
    keyfile_path: Optional[str | Path],
    salt: bytes
) -> bytes:
    """
    Derive 256-bit master key using Scrypt combining password and keyfile bytes.
    """
    keyfile_hash = _read_keyfile(keyfile_path)
    pwd_bytes = password.encode("utf-8") if password else b""

    if not pwd_bytes and not keyfile_hash:
        raise ValueError("At least a password or a keyfile is required to protect the vault.")

    combined_secret = pwd_bytes + b":" + keyfile_hash
    return hashlib.scrypt(
        combined_secret,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32
    )


class VaultArchive:
    """Internal serialization of directory trees into a compact compressed binary archive."""

    @staticmethod
    def pack(source_dir: Path) -> bytes:
        if not source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {source_dir}")

        entries: List[Dict[str, Any]] = []
        payloads: List[bytes] = []

        for root, _, files in os.walk(source_dir):
            for f in files:
                file_path = Path(root) / f
                rel_path = file_path.relative_to(source_dir).as_posix()
                content = file_path.read_bytes()
                stat = file_path.stat()

                entries.append({
                    "path": rel_path,
                    "size": len(content),
                    "mtime": stat.st_mtime,
                })
                payloads.append(content)

        manifest_bytes = json.dumps(entries).encode("utf-8")
        raw_stream = bytearray()
        raw_stream.extend(struct.pack(">I", len(manifest_bytes)))
        raw_stream.extend(manifest_bytes)
        for p in payloads:
            raw_stream.extend(p)

        return zlib.compress(bytes(raw_stream), level=9)

    @staticmethod
    def unpack(packed_data: bytes, output_dir: Path) -> List[str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_stream = zlib.decompress(packed_data)

        manifest_len = struct.unpack(">I", raw_stream[:4])[0]
        manifest_bytes = raw_stream[4:4 + manifest_len]
        entries: List[Dict[str, Any]] = json.loads(manifest_bytes.decode("utf-8"))

        offset = 4 + manifest_len
        extracted_files = []

        for entry in entries:
            rel_path = entry["path"]
            file_size = entry["size"]
            content = raw_stream[offset:offset + file_size]
            offset += file_size

            dest_path = output_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(content)
            if "mtime" in entry:
                try:
                    os.utime(dest_path, (entry["mtime"], entry["mtime"]))
                except Exception:
                    pass
            extracted_files.append(rel_path)

        return extracted_files

    @staticmethod
    def list_entries(packed_data: bytes) -> List[Dict[str, Any]]:
        raw_stream = zlib.decompress(packed_data)
        manifest_len = struct.unpack(">I", raw_stream[:4])[0]
        manifest_bytes = raw_stream[4:4 + manifest_len]
        return json.loads(manifest_bytes.decode("utf-8"))


def create_vault(
    source_dir: str | Path,
    vault_path: str | Path,
    password: Optional[str] = None,
    keyfile_path: Optional[str | Path] = None,
    cipher: str = "chacha20"
) -> Path:
    """
    Pack an entire directory tree into a single encrypted, authenticated .vault container.

    Args:
        source_dir: Directory containing files to protect.
        vault_path: Output file path for the .vault archive.
        password: Optional master password (MFA factor 1).
        keyfile_path: Optional keyfile path (MFA factor 2).
        cipher: Encryption cipher: 'chacha20' (ChaCha20-Poly1305) or 'aes' (AES-256-GCM).

    Returns:
        Path of the generated vault container.
    """
    src = Path(source_dir)
    dest = Path(vault_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    archive_data = VaultArchive.pack(src)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    master_key = _derive_vault_key(password, keyfile_path, salt)

    cipher_id = 0x01 if cipher.lower() == "aes" else 0x02

    # Header: MAGIC(8) + CIPHER_ID(1) + SALT(16) + NONCE(12)
    header = VAULT_MAGIC + bytes([cipher_id]) + salt + nonce

    if cipher_id == 0x01:
        ciphertext, tag = aes256_gcm_encrypt(master_key, nonce, archive_data, header)
    else:
        ciphertext, tag = chacha20_poly1305_encrypt(master_key, nonce, archive_data, header)

    container = header + tag + ciphertext
    dest.write_bytes(container)
    return dest


def extract_vault(
    vault_path: str | Path,
    output_dir: str | Path,
    password: Optional[str] = None,
    keyfile_path: Optional[str | Path] = None
) -> List[str]:
    """
    Decrypt and extract an encrypted .vault container back into a directory tree.

    Returns:
        List of extracted relative file paths.
    """
    vp = Path(vault_path)
    if not vp.exists():
        raise FileNotFoundError(f"Vault container not found: {vp}")

    data = vp.read_bytes()
    if not data.startswith(VAULT_MAGIC):
        raise ValueError("Invalid vault format: missing EncryptorVault header.")

    offset = len(VAULT_MAGIC)
    cipher_id = data[offset]
    offset += 1
    salt = data[offset:offset + 16]
    offset += 16
    nonce = data[offset:offset + 12]
    offset += 12
    tag = data[offset:offset + 16]
    offset += 16
    ciphertext = data[offset:]

    header = data[:len(VAULT_MAGIC) + 1 + 16 + 12]
    master_key = _derive_vault_key(password, keyfile_path, salt)

    if cipher_id == 0x01:
        archive_data = aes256_gcm_decrypt(master_key, nonce, ciphertext, tag, header)
    elif cipher_id == 0x02:
        archive_data = chacha20_poly1305_decrypt(master_key, nonce, ciphertext, tag, header)
    else:
        raise ValueError(f"Unknown cipher ID in vault: {cipher_id}")

    return VaultArchive.unpack(archive_data, Path(output_dir))


def inspect_vault(
    vault_path: str | Path,
    password: Optional[str] = None,
    keyfile_path: Optional[str | Path] = None
) -> Dict[str, Any]:
    """
    Inspect the contents of a vault without extracting files to disk.
    """
    vp = Path(vault_path)
    data = vp.read_bytes()
    if not data.startswith(VAULT_MAGIC):
        raise ValueError("Invalid vault container.")

    offset = len(VAULT_MAGIC)
    cipher_id = data[offset]
    offset += 1
    salt = data[offset:offset + 16]
    offset += 16
    nonce = data[offset:offset + 12]
    offset += 12
    tag = data[offset:offset + 16]
    offset += 16
    ciphertext = data[offset:]

    header = data[:len(VAULT_MAGIC) + 1 + 16 + 12]
    master_key = _derive_vault_key(password, keyfile_path, salt)

    if cipher_id == 0x01:
        archive_data = aes256_gcm_decrypt(master_key, nonce, ciphertext, tag, header)
        cipher_name = "AES-256-GCM"
    else:
        archive_data = chacha20_poly1305_decrypt(master_key, nonce, ciphertext, tag, header)
        cipher_name = "ChaCha20-Poly1305"

    entries = VaultArchive.list_entries(archive_data)
    total_size = sum(e["size"] for e in entries)

    return {
        "vault_file": vp.name,
        "cipher": cipher_name,
        "file_count": len(entries),
        "total_uncompressed_bytes": total_size,
        "files": entries,
    }
