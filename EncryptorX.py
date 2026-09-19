#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
EncryptorX - Motor Criptográfico, GUI Moderna y Librería Todo-en-Uno
=============================================================================
Versión: 3.0.0
Autor: GhostMoai / Antigravity

Características principales:
- Cero dependencias externas (utiliza únicamente la biblioteca estándar de Python).
- Funciona como:
    1. Librería de Python: `import EncryptorX`
    2. Aplicación de Escritorio con GUI moderna (Tkinter dark theme)
    3. Herramienta de Línea de Comandos (CLI)
- Cifrado propio Null-Obfuscated Cipher:
    - Clave de 256 bits y mensaje viajan en el mismo texto.
    - Ofuscación con patrones "NULL" (NU..LL, LL..LL, n..ull, null..null) y ruido.
    - Integridad y autenticidad reforzada con HMAC-SHA256 (anti-manipulación).
    - Enmascaramiento de clave con Nonce para evitar exposición en texto plano.
    - Soporte opcional de contraseña/PIN con derivación PBKDF2-HMAC-SHA256.
    - Delimitadores configurables: $, %, &, #, ?
    - Retrocompatibilidad con Base64 tradicional.
=============================================================================
"""

from __future__ import annotations

import os
import sys
import re
import hmac
import base64
import secrets
import hashlib
import argparse
from pathlib import Path
from typing import Optional, Tuple, List

# ---------------------------------------------------------------------------
# Constantes Globales
# ---------------------------------------------------------------------------
__version__ = "3.2.0"
__app_name__ = "EncryptorX"

SEPARATORS = ['$', '%', '&', '#']
DEFAULT_SEPARATOR = '$'
NONCE_SIZE = 16       # 128-bit Nonce
KEY_SIZE = 32         # 256-bit Key
TAG_SIZE = 16         # 128-bit HMAC-SHA256 Auth Tag
SALT_SIZE = 16        # 128-bit PBKDF2/Scrypt Salt
PBKDF2_ROUNDS = 600_000 # OWASP standard iteration count
SCRYPT_N = 16384      # Scrypt CPU/memory cost (16 MB RAM)
SCRYPT_R = 8          # Scrypt block size
SCRYPT_P = 1          # Scrypt parallelization parameter

FLAG_DIRECT = 0x00
FLAG_PBKDF2 = 0x01
FLAG_SCRYPT = 0x02
FLAG_DOUBLE_DIRECT = 0x10
FLAG_DOUBLE_CASCADE = 0x12

# ---------------------------------------------------------------------------
# Catálogo Ofuscado de 64 Combinaciones Simbólicas y 64 Envoltorios Legacy
# (Literales cifrados con máscara XOR para prevenir robo y análisis estático)
# ---------------------------------------------------------------------------
_OBFUSCATED_KEY = bytes([
    0x5A, 0xC3, 0x91, 0x47, 0x1E, 0x88, 0x62, 0xF5, 0x33, 0xAA, 0x09, 0x7D, 0xB6, 0x44, 0x2C, 0x9F
])

_OBFUSCATED_SYMBOLIC_BLOB = bytes([
    0x01, 0xf3, 0xca, 0x58, 0x43, 0xb8, 0x3f, 0xeb, 0x68, 0x9b, 0x52, 0x62,
    0xeb, 0x75, 0x71, 0x81, 0x01, 0xf1, 0xca, 0x58, 0x43, 0xba, 0x3f, 0xeb,
    0x68, 0x99, 0x52, 0x62, 0xeb, 0x77, 0x71, 0x81, 0x21, 0xf7, 0xea, 0x58,
    0x63, 0xbc, 0x1f, 0xeb, 0x48, 0x9f, 0x72, 0x62, 0xcb, 0x71, 0x51, 0x81,
    0x21, 0xf5, 0xea, 0x58, 0x63, 0xbe, 0x1f, 0xeb, 0x48, 0x9d, 0x72, 0x62,
    0xcb, 0x73, 0x51, 0x81, 0x72, 0xfb, 0xb9, 0x58, 0x37, 0xb0, 0x4b, 0xeb,
    0x1b, 0x93, 0x21, 0x62, 0x9f, 0x7d, 0x05, 0x81, 0x01, 0xf3, 0xcc, 0x58,
    0x45, 0xb8, 0x3f, 0xeb, 0x48, 0x9b, 0x74, 0x62, 0xcd, 0x75, 0x51, 0x81,
    0x72, 0xf1, 0xb8, 0x58, 0x36, 0xba, 0x4b, 0xeb, 0x0f, 0x99, 0x37, 0x62,
    0x8a, 0x77, 0x12, 0x81, 0x01, 0xf7, 0xcc, 0x58, 0x45, 0xbc, 0x3f, 0xeb,
    0x48, 0x9f, 0x74, 0x62, 0xcd, 0x71, 0x51, 0x81, 0x66, 0xbf, 0x8e, 0x3b,
    0x20, 0x96, 0x5e, 0xc8, 0x2c, 0x97, 0x37, 0x63, 0x8a, 0x69, 0x33, 0xb2,
    0x64, 0xdd, 0xad, 0x39, 0x01, 0xf6, 0x5c, 0xeb, 0x0f, 0x81, 0x16, 0x56,
    0x88, 0x5a, 0x10, 0xa3, 0x45, 0xfd, 0xaf, 0x59, 0x20, 0xb6, 0x7d, 0xc9,
    0x0f, 0xb4, 0x37, 0x01, 0xa9, 0x38, 0x10, 0x81, 0x66, 0xe9, 0x8e, 0x6d,
    0x20, 0x96, 0x5e, 0xab, 0x2c, 0xf4, 0x37, 0x63, 0x8a, 0x04, 0x33, 0xdf,
    0x64, 0xdd, 0xad, 0x66, 0x01, 0xa9, 0x5c, 0xeb, 0x4d, 0xd4, 0x16, 0x03,
    0xc8, 0x5a, 0x72, 0xc1, 0x45, 0x9d, 0xcf, 0x59, 0x34, 0xa2, 0x7d, 0xdf,
    0x19, 0xb4, 0x22, 0x56, 0xa9, 0x6f, 0x07, 0x81, 0x67, 0xfe, 0x8e, 0x7a,
    0x23, 0x96, 0x58, 0xcf, 0x2c, 0x90, 0x33, 0x63, 0x8d, 0x7f, 0x33, 0xa4,
    0x61, 0xdd, 0xed, 0x3b, 0x01, 0xf4, 0x1e, 0xeb, 0x12, 0xd4, 0x28, 0x62,
    0x97, 0x3a, 0x0d, 0x81, 0x65, 0xe9, 0xae, 0x58, 0x21, 0xa2, 0x5d, 0xeb,
    0x73, 0xf4, 0x49, 0x62, 0xf6, 0x1a, 0x6c, 0x81, 0x71, 0xf9, 0xba, 0x58,
    0x35, 0xb2, 0x49, 0xeb, 0x12, 0x9a, 0x28, 0x62, 0x97, 0x74, 0x0d, 0x81,
    0x65, 0xf2, 0xae, 0x58, 0x21, 0xb9, 0x5d, 0xeb, 0x19, 0x98, 0x23, 0x62,
    0x9c, 0x76, 0x06, 0x81, 0x04, 0xf0, 0xcf, 0x58, 0x40, 0xbb, 0x3c, 0xeb,
    0x73, 0x9e, 0x49, 0x62, 0xf6, 0x70, 0x6c, 0x81, 0x24, 0xf6, 0xef, 0x58,
    0x60, 0xbd, 0x1c, 0xeb, 0x09, 0x9c, 0x33, 0x62, 0x8c, 0x72, 0x16, 0x81,
    0x61, 0xf4, 0xaa, 0x58, 0x25, 0xbf, 0x59, 0xeb, 0x18, 0x92, 0x22, 0x62,
    0x9d, 0x7c, 0x07, 0x81, 0x67, 0xfa, 0xac, 0x58, 0x23, 0xb1, 0x5f, 0xeb,
    0x4f, 0x9a, 0x75, 0x62, 0xca, 0x74, 0x50, 0x81, 0x75, 0xf2, 0xbe, 0x58,
    0x31, 0xb9, 0x4d, 0xeb, 0x4d, 0x90, 0x16, 0x47, 0xc8, 0x5a, 0x72, 0xbe,
    0x45, 0xe2, 0xcf, 0x59, 0x34, 0xa3, 0x7d, 0xde, 0x19, 0xb4, 0x49, 0x40,
    0xa9, 0x79, 0x6c, 0x81, 0x26, 0xbd, 0x8e, 0x39, 0x62, 0x96, 0x3c, 0x8b,
    0x2c, 0xd4, 0x57, 0x63, 0x97, 0x3a, 0x33, 0xe1, 0x7b, 0xdd, 0xae, 0x6c,
    0x01, 0xa3, 0x5d, 0xeb, 0x1b, 0xea, 0x16, 0x3d, 0x9f, 0x5a, 0x57, 0xc1,
    0x45, 0x9d, 0xec, 0x59, 0x22, 0xf6, 0x7d, 0x8b, 0x0d, 0xb4, 0x37, 0x03,
    0xa9, 0x3a, 0x10,
])

_OBFUSCATED_LEGACY_BLOB = bytes([
    0x14, 0x96, 0x8e, 0x0b, 0x52, 0x96, 0x0c, 0x80, 0x2c, 0xc6, 0x65, 0x63,
    0xf8, 0x31, 0x33, 0xf3, 0x36, 0xdd, 0xff, 0x12, 0x01, 0xe4, 0x0e, 0xeb,
    0x7d, 0xff, 0x16, 0x11, 0xda, 0x5a, 0x42, 0xea, 0x45, 0x8f, 0xdd, 0x59,
    0x50, 0xfd, 0x7d, 0xb9, 0x7f, 0xb4, 0x67, 0x28, 0xa9, 0x08, 0x60, 0x81,
    0x14, 0x96, 0x8e, 0x0b, 0x72, 0x96, 0x0c, 0x80, 0x2c, 0xe6, 0x65, 0x63,
    0xf8, 0x31, 0x33, 0xf3, 0x16, 0xdd, 0xdf, 0x12, 0x01, 0xe4, 0x2e, 0xeb,
    0x7f, 0xe6, 0x16, 0x31, 0xfa, 0x5a, 0x40, 0xf3, 0x45, 0xaf, 0xfd, 0x59,
    0x52, 0xe4, 0x7d, 0x99, 0x5f, 0xb4, 0x65, 0x31, 0xa9, 0x28, 0x40, 0x81,
    0x16, 0x8f, 0x8e, 0x2b, 0x72, 0x96, 0x0e, 0x99, 0x2c, 0xe6, 0x45, 0x63,
    0xfa, 0x28, 0x33, 0xd3, 0x16, 0xdd, 0xfd, 0x0b, 0x01, 0xc4, 0x2e, 0xeb,
    0x5d, 0xb5, 0x7c, 0x11, 0xda, 0x5a, 0x62, 0x80, 0x2f, 0xaf, 0xfd, 0x59,
    0x70, 0x97, 0x37, 0xb9, 0x7f, 0xb4, 0x47, 0x62, 0xe3, 0x08, 0x60, 0x81,
    0x34, 0xdc, 0xc4, 0x2b, 0x72, 0x96, 0x2c, 0xea, 0x46, 0xe6, 0x65, 0x63,
    0xd8, 0x5b, 0x59, 0xf3, 0x16, 0xdd, 0xdf, 0x58, 0x4b, 0xe4, 0x2e, 0xeb,
    0x5d, 0xdf, 0x16, 0x11, 0xa8, 0x0a, 0x79, 0x80, 0x16, 0xdd, 0xdf, 0x32,
    0x01, 0xc4, 0x7c, 0x9b, 0x66, 0xb5, 0x65, 0x63, 0xd8, 0x31, 0x40, 0xf3,
    0x45, 0xad, 0xe4, 0x2b, 0x72, 0x96, 0x2c, 0xa0, 0x7f, 0xe6, 0x16, 0x33,
    0xe3, 0x08, 0x60, 0x81, 0x14, 0xb6, 0xfd, 0x2b, 0x01, 0xc6, 0x17, 0x99,
    0x5f, 0xb4, 0x67, 0x28, 0xfa, 0x08, 0x33, 0xf1, 0x0f, 0x8f, 0xdd, 0x59,
    0x50, 0xfd, 0x0e, 0xb9, 0x2c, 0xe4, 0x7c, 0x11, 0xfa, 0x5a, 0x42, 0xea,
    0x16, 0x8f, 0x8e, 0x29, 0x6b, 0xc4, 0x2e, 0xeb, 0x7d, 0xff, 0x65, 0x11,
    0xa9, 0x0a, 0x79, 0xf3, 0x36, 0xdd, 0xff, 0x32, 0x72, 0xc4, 0x7d, 0x9b,
    0x46, 0xc6, 0x45, 0x63, 0xd8, 0x31, 0x40, 0xf3, 0x45, 0x8d, 0xc4, 0x0b,
    0x52, 0x96, 0x2c, 0xa0, 0x7f, 0xe6, 0x16, 0x13, 0xc3, 0x28, 0x40, 0x81,
    0x14, 0xb6, 0xfd, 0x2b, 0x01, 0xc6, 0x37, 0xb9, 0x7f, 0xb4, 0x47, 0x28,
    0xfa, 0x08, 0x33, 0xd1, 0x2f, 0xaf, 0xfd, 0x59, 0x50, 0xc4, 0x7d, 0xa0,
    0x7f, 0xb4, 0x67, 0x11, 0xa9, 0x31, 0x40, 0x81, 0x14, 0xaf, 0x8e, 0x32,
    0x52, 0x96, 0x0c, 0xb9, 0x2c, 0xff, 0x65, 0x63, 0xf8, 0x08, 0x33, 0xea,
    0x36, 0xdd, 0xff, 0x2b, 0x01, 0xdd, 0x2e, 0xeb, 0x66, 0xe6, 0x16, 0x33,
    0xfa, 0x5a, 0x59, 0xf3, 0x45, 0xad, 0xfd, 0x59, 0x4b, 0xe4, 0x7d, 0xbb,
    0x5f, 0xb4, 0x7c, 0x31, 0xa9, 0x2a, 0x60, 0x81, 0x0f, 0x8d, 0x8e, 0x0b,
    0x52, 0x96, 0x17, 0x9b, 0x2c, 0xc6, 0x65, 0x63, 0xe3, 0x2a, 0x33, 0xf3,
    0x36, 0xdd, 0xe4, 0x09, 0x01, 0xc4, 0x2e, 0xeb, 0x7f, 0xe6, 0x16, 0x28,
    0xf8, 0x5a, 0x40, 0xf3, 0x45, 0xb6, 0xff, 0x59, 0x52, 0xe4, 0x7d, 0x80,
    0x5d, 0xb4, 0x65, 0x31, 0xa9, 0x11, 0x62, 0x81, 0x14, 0x96, 0xdd, 0x58,
    0x52, 0x96, 0x0c, 0x80, 0x5f, 0xb5, 0x65,
])

def _unpack_obfuscated_wrappers(blob: bytes, key: bytes) -> List[Tuple[str, str]]:
    raw = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob)).decode("utf-8")
    return [tuple(chunk.split("\x1f")) for chunk in raw.split("\x1e")]

SYMBOLIC_WRAPPERS: List[Tuple[str, str]] = _unpack_obfuscated_wrappers(_OBFUSCATED_SYMBOLIC_BLOB, _OBFUSCATED_KEY)
_LEGACY_NULL_WRAPPERS: List[Tuple[str, str]] = _unpack_obfuscated_wrappers(_OBFUSCATED_LEGACY_BLOB, _OBFUSCATED_KEY)
_ALL_WRAPPERS = SYMBOLIC_WRAPPERS + _LEGACY_NULL_WRAPPERS

# Expresión regular precompilada y ultra-eficiente para las combinaciones
_DEOBFUSCATE_REGEX = re.compile(
    r'(?:' + '|'.join(f'{re.escape(pre)}([0-9a-fA-F]{{2}}){re.escape(post)}' for pre, post in _ALL_WRAPPERS) + r')'
)

# ---------------------------------------------------------------------------
# Primitivas Criptográficas y de Flujo (Stream Cipher & HMAC)
# ---------------------------------------------------------------------------

def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Genera un flujo pseudoaleatorio de bytes usando SHA-256 en modo contador."""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        h = hashlib.sha256(key + nonce + counter.to_bytes(4, 'big'))
        keystream.extend(h.digest())
        counter += 1
    return bytes(keystream[:length])

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Aplica operación XOR bit a bit entre dos secuencias de bytes."""
    return bytes(x ^ y for x, y in zip(a, b))

def _derive_auth_key(key: bytes) -> bytes:
    """Deriva una clave independiente para autenticación HMAC-SHA256."""
    return hashlib.sha256(b"ENCRYPTORX_AUTH_TAG_SALT:" + key).digest()

# ---------------------------------------------------------------------------
# Ofuscación y Desofuscación con Símbolos, Números y Ruido
# ---------------------------------------------------------------------------

def _generate_safe_noise(min_len: int = 2, max_len: int = 6) -> str:
    """
    Genera ruido aleatorio compuesto por letras alfabéticas limpias,
    excluyendo deliberadamente 'n, u, l, N, U, L' para garantizar que
    no aparezca ninguna traza ni coincidencia fortuita de la palabra 'null'.
    """
    safe_chars = "abcdefghjkmopqrstwxyzABCDEFGHJKMOPQRSTWXYZ"
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(safe_chars) for _ in range(length))

def _obfuscate_byte_hex(hex_str: str) -> str:
    """
    Toma una cadena hexadecimal de bytes (2 caracteres hex por byte).
    Envuelve cada byte seleccionando aleatoriamente entre los 64 envoltorios simbólicos/numéricos
    e intercala conectores y ruido alfabético.
    """
    chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    parts = []
    connectors = ["=", "_", "-", "~", "+", ""]
    num_wrappers = len(SYMBOLIC_WRAPPERS)
    for chunk in chunks:
        pre_noise = _generate_safe_noise(2, 5)
        post_noise = _generate_safe_noise(2, 5)
        pre_wrap, post_wrap = SYMBOLIC_WRAPPERS[secrets.randbelow(num_wrappers)]
        wrapper = f"{pre_wrap}{chunk}{post_wrap}"
        conn = secrets.choice(connectors)
        parts.append(f"{pre_noise}{conn}{wrapper}{conn}{post_noise}")
    return "".join(parts)

def _is_mostly_text(text: str) -> bool:
    """Verifica si el texto decodificado es mayoritariamente legible y no ruido binario aleatorio."""
    if not text:
        return False
    valid_chars = sum(1 for c in text if (c.isprintable() or c in "\n\r\t") and c != '\ufffd')
    return (valid_chars / len(text)) >= 0.70


def _deobfuscate_byte_hex(obfuscated_str: str) -> str:
    """Extrae todos los bytes de 2 caracteres hex contenidos en envoltorios simbólicos, numéricos o legacy."""
    matches = [next(g for g in m.groups() if g is not None) for m in _DEOBFUSCATE_REGEX.finditer(obfuscated_str)]
    res = "".join(matches)
    if len(res) % 2 != 0:
        res = res[:-1]
    return res


def _unwrap_key_from_package(
    raw_key_package: bytes,
    password: Optional[str],
    nonce_bytes: bytes,
    ciphertext_bytes: bytes,
    auth_tag: bytes,
    tolerant: bool = False
) -> bytes:
    """
    Desempaqueta y descifra la clave simétrica según el flag de protección.
    Soporta:
      - FLAG_DIRECT (0x00): Modo auto-descifrable directo.
      - FLAG_PBKDF2 (0x01): Blindaje PBKDF2 600,000 iteraciones (con fallback 100k).
      - FLAG_SCRYPT (0x02): Blindaje Memory-Hard Scrypt (16 MB RAM por intento).
      - FLAG_DOUBLE_DIRECT (0x10): Capa exterior de doble cifrado directo.
      - FLAG_DOUBLE_CASCADE (0x12): Capa exterior de doble cifrado protegido con PBKDF2 600k.
    """
    if not raw_key_package:
        return b"\x00" * KEY_SIZE

    flag = raw_key_package[0]

    if flag == FLAG_SCRYPT:
        if not password:
            raise ValueError("Este mensaje requiere contraseña (blindaje Scrypt) para descifrar.")
        if len(raw_key_package) < 1 + SALT_SIZE + KEY_SIZE:
            if tolerant:
                raw_key_package = raw_key_package.ljust(1 + SALT_SIZE + KEY_SIZE, b"\x00")
            else:
                raise ValueError("Estructura de clave Scrypt dañada.")
        salt = raw_key_package[1:1 + SALT_SIZE]
        enc_key = raw_key_package[1 + SALT_SIZE:1 + SALT_SIZE + KEY_SIZE]
        wrapping_key = hashlib.scrypt(
            password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_SIZE
        )
        return _xor_bytes(enc_key, _generate_keystream(wrapping_key, salt, KEY_SIZE))

    elif flag in (FLAG_PBKDF2, FLAG_DOUBLE_CASCADE):
        if not password:
            raise ValueError("Este mensaje requiere contraseña para descifrar.")
        if len(raw_key_package) < 1 + SALT_SIZE + KEY_SIZE:
            if tolerant:
                raw_key_package = raw_key_package.ljust(1 + SALT_SIZE + KEY_SIZE, b"\x00")
            else:
                raise ValueError("Estructura de clave con contraseña dañada.")
        salt = raw_key_package[1:1 + SALT_SIZE]
        enc_key = raw_key_package[1 + SALT_SIZE:1 + SALT_SIZE + KEY_SIZE]

        # 1. Probar primero con el estándar reforzado de 600,000 iteraciones (OWASP)
        wrapping_key = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
        )
        cand_key = _xor_bytes(enc_key, _generate_keystream(wrapping_key, salt, KEY_SIZE))
        cand_auth = _derive_auth_key(cand_key)
        cand_tag = hmac.new(
            cand_auth, raw_key_package + nonce_bytes + ciphertext_bytes, hashlib.sha256
        ).digest()[:TAG_SIZE]
        if hmac.compare_digest(auth_tag, cand_tag):
            return cand_key

        # 2. Fallback a 100,000 iteraciones para tokens legacy
        wrapping_key_legacy = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, 100_000, dklen=KEY_SIZE
        )
        cand_key_legacy = _xor_bytes(enc_key, _generate_keystream(wrapping_key_legacy, salt, KEY_SIZE))
        cand_auth_legacy = _derive_auth_key(cand_key_legacy)
        cand_tag_legacy = hmac.new(
            cand_auth_legacy, raw_key_package + nonce_bytes + ciphertext_bytes, hashlib.sha256
        ).digest()[:TAG_SIZE]
        if hmac.compare_digest(auth_tag, cand_tag_legacy):
            return cand_key_legacy

        return cand_key

    elif flag in (FLAG_DIRECT, FLAG_DOUBLE_DIRECT):
        if len(raw_key_package) < 1 + KEY_SIZE:
            if tolerant:
                return raw_key_package[1:].ljust(KEY_SIZE, b"\x00")[:KEY_SIZE]
            raise ValueError("Estructura de clave dañada.")
        return raw_key_package[1:1 + KEY_SIZE]

    else:
        # Retrocompatibilidad para versiones pre-flag
        if len(raw_key_package) >= KEY_SIZE:
            return raw_key_package[:KEY_SIZE]
        if tolerant:
            return raw_key_package.ljust(KEY_SIZE, b"\x00")[:KEY_SIZE]
        raise ValueError(f"Formato de clave desconocido: {flag:#x}")


# ---------------------------------------------------------------------------
# API Pública de Cifrado y Descifrado de Texto
# ---------------------------------------------------------------------------

def encrypt(
    text: str,
    password: Optional[str] = None,
    delimiter: Optional[str] = None,
    use_scrypt: bool = True,
    double_layer: bool = True
) -> str:
    """
    Cifra un texto generando un token auto-contenido con envoltorios simbólicos y numéricos.
    Por defecto, aplica doble cifrado en cascada (Dual-Key Cascade) con Scrypt (capa interna)
    y PBKDF2 600k (capa externa) cuando se suministra contraseña.
    Si delimiter es None (por defecto), integra TODOS los separadores ($, %, &, #) en el token.
    Si se especifica un delimiter puntual, opera en modo legacy de un solo separador.
    """
    if not text:
        return ""

    if double_layer and delimiter is None:
        # =====================================================================
        # DOBLE CIFRADO EN CASCADA (DUAL-KEY CASCADE)
        # =====================================================================
        # --- CAPA 1 (Interna) ---
        k1 = secrets.token_bytes(KEY_SIZE)
        n1 = secrets.token_bytes(NONCE_SIZE)
        if password:
            salt1 = secrets.token_bytes(SALT_SIZE)
            if use_scrypt:
                wrap_k1 = hashlib.scrypt(
                    password.encode('utf-8'), salt=salt1, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_SIZE
                )
                enc_k1 = _xor_bytes(k1, _generate_keystream(wrap_k1, salt1, KEY_SIZE))
                raw_pkg_1 = bytes([FLAG_SCRYPT]) + salt1 + enc_k1
            else:
                wrap_k1 = hashlib.pbkdf2_hmac(
                    'sha256', password.encode('utf-8'), salt1, PBKDF2_ROUNDS, dklen=KEY_SIZE
                )
                enc_k1 = _xor_bytes(k1, _generate_keystream(wrap_k1, salt1, KEY_SIZE))
                raw_pkg_1 = bytes([FLAG_PBKDF2]) + salt1 + enc_k1
        else:
            raw_pkg_1 = bytes([FLAG_DIRECT]) + k1

        pt_bytes = text.encode('utf-8')
        ks1 = _generate_keystream(k1, n1, len(pt_bytes))
        c1 = _xor_bytes(pt_bytes, ks1)
        auth_k1 = _derive_auth_key(k1)
        tag1 = hmac.new(
            auth_k1,
            raw_pkg_1 + n1 + c1,
            hashlib.sha256
        ).digest()[:TAG_SIZE]

        # Inner blob encapsulado
        inner_blob = len(raw_pkg_1).to_bytes(2, 'big') + raw_pkg_1 + n1 + tag1 + c1

        # --- CAPA 2 (Externa) ---
        k2 = secrets.token_bytes(KEY_SIZE)
        n2 = secrets.token_bytes(NONCE_SIZE)
        if password:
            salt2 = secrets.token_bytes(SALT_SIZE)
            wrap_k2 = hashlib.pbkdf2_hmac(
                'sha256', password.encode('utf-8'), salt2, PBKDF2_ROUNDS, dklen=KEY_SIZE
            )
            enc_k2 = _xor_bytes(k2, _generate_keystream(wrap_k2, salt2, KEY_SIZE))
            raw_pkg_2 = bytes([FLAG_DOUBLE_CASCADE]) + salt2 + enc_k2
        else:
            raw_pkg_2 = bytes([FLAG_DOUBLE_DIRECT]) + k2

        ks2 = _generate_keystream(k2, n2, len(inner_blob))
        c2 = _xor_bytes(inner_blob, ks2)
        auth_k2 = _derive_auth_key(k2)
        full_mac2 = hmac.new(
            auth_k2,
            raw_pkg_2 + n2 + c2,
            hashlib.sha256
        ).digest()
        tag2 = full_mac2[:TAG_SIZE]
        crc2 = hashlib.sha256(full_mac2).digest()[:4]

        mask2 = _generate_keystream(n2, b"ENCRYPTORX_KEY_MASK", len(raw_pkg_2))
        masked_pkg_2 = _xor_bytes(raw_pkg_2, mask2)

        obf_key = _obfuscate_byte_hex(masked_pkg_2.hex())
        obf_nonce = _obfuscate_byte_hex(n2.hex())
        obf_tag = _obfuscate_byte_hex(tag2.hex())
        obf_cipher = _obfuscate_byte_hex(c2.hex())
        obf_crc = _obfuscate_byte_hex(crc2.hex())
        return f"{obf_key}${obf_nonce}%{obf_tag}&{obf_cipher}#{obf_crc}"

    # =====================================================================
    # MODO DE CAPA ÚNICA (LEGACY O SINGLE-DELIMITER)
    # =====================================================================
    key_bytes = secrets.token_bytes(KEY_SIZE)
    nonce_bytes = secrets.token_bytes(NONCE_SIZE)

    if password:
        salt = secrets.token_bytes(SALT_SIZE)
        if use_scrypt:
            wrapping_key = hashlib.scrypt(
                password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_SIZE
            )
            enc_key = _xor_bytes(key_bytes, _generate_keystream(wrapping_key, salt, KEY_SIZE))
            raw_key_package = bytes([FLAG_SCRYPT]) + salt + enc_key
        else:
            wrapping_key = hashlib.pbkdf2_hmac(
                'sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
            )
            enc_key = _xor_bytes(key_bytes, _generate_keystream(wrapping_key, salt, KEY_SIZE))
            raw_key_package = bytes([FLAG_PBKDF2]) + salt + enc_key
    else:
        raw_key_package = bytes([FLAG_DIRECT]) + key_bytes

    plaintext_bytes = text.encode('utf-8')
    keystream = _generate_keystream(key_bytes, nonce_bytes, len(plaintext_bytes))
    ciphertext_bytes = _xor_bytes(plaintext_bytes, keystream)

    auth_key = _derive_auth_key(key_bytes)
    full_mac = hmac.new(
        auth_key,
        raw_key_package + nonce_bytes + ciphertext_bytes,
        hashlib.sha256
    ).digest()
    auth_tag = full_mac[:TAG_SIZE]

    mask = _generate_keystream(nonce_bytes, b"ENCRYPTORX_KEY_MASK", len(raw_key_package))
    masked_key_package = _xor_bytes(raw_key_package, mask)

    if delimiter in SEPARATORS:
        payload_package = nonce_bytes + auth_tag + ciphertext_bytes
        obf_key = _obfuscate_byte_hex(masked_key_package.hex())
        obf_payload = _obfuscate_byte_hex(payload_package.hex())
        return f"{obf_key}{delimiter}{obf_payload}"
    else:
        crc = hashlib.sha256(full_mac).digest()[:4]
        obf_key = _obfuscate_byte_hex(masked_key_package.hex())
        obf_nonce = _obfuscate_byte_hex(nonce_bytes.hex())
        obf_tag = _obfuscate_byte_hex(auth_tag.hex())
        obf_cipher = _obfuscate_byte_hex(ciphertext_bytes.hex())
        obf_crc = _obfuscate_byte_hex(crc.hex())
        return f"{obf_key}${obf_nonce}%{obf_tag}&{obf_cipher}#{obf_crc}"

def decrypt(token: str, password: Optional[str] = None, strict: bool = False) -> str:
    """
    Descifra un token cifrado con recuperación tolerante a fallos y pérdida de datos.
    Detecta automáticamente si es multi-separador ($, %, &, #), legacy o Base64.
    Soporta Doble Cifrado en Cascada (Dual-Key), Scrypt, PBKDF2 (600k y 100k) y modo directo.
    Si strict es False (por defecto), muestra el texto descifrado recuperable incluso
    si el token sufrió pérdida de caracteres, truncamiento o adulteración parcial.
    """
    if not token:
        return ""

    cleaned = token.strip()

    # 1. Detección de formato multi-separador (contiene $, %, &, #)
    if all(s in cleaned for s in ['$', '%', '&', '#']):
        p_key, rest1 = cleaned.split('$', 1)
        p_nonce, rest2 = rest1.split('%', 1)
        p_tag, rest3 = rest2.split('&', 1)
        p_cipher, _p_crc = rest3.split('#', 1)

        nonce_hex = _deobfuscate_byte_hex(p_nonce)
        nonce_bytes = (bytes.fromhex(nonce_hex) if nonce_hex else b"").ljust(NONCE_SIZE, b"\x00")[:NONCE_SIZE]

        auth_tag_hex = _deobfuscate_byte_hex(p_tag)
        auth_tag = (bytes.fromhex(auth_tag_hex) if auth_tag_hex else b"").ljust(TAG_SIZE, b"\x00")[:TAG_SIZE]

        ciphertext_hex = _deobfuscate_byte_hex(p_cipher)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex) if ciphertext_hex else b""

        masked_key_hex = _deobfuscate_byte_hex(p_key)
        if not masked_key_hex:
            raise ValueError("Clave corrupta o no encontrada en el token.")
        masked_key_package = bytes.fromhex(masked_key_hex)
        mask = _generate_keystream(nonce_bytes, b"ENCRYPTORX_KEY_MASK", len(masked_key_package))
        raw_key_package = _xor_bytes(masked_key_package, mask)

        key_bytes = _unwrap_key_from_package(
            raw_key_package, password, nonce_bytes, ciphertext_bytes, auth_tag, tolerant=True
        )

        auth_key = _derive_auth_key(key_bytes)
        expected_tag = hmac.new(
            auth_key,
            raw_key_package + nonce_bytes + ciphertext_bytes,
            hashlib.sha256
        ).digest()[:TAG_SIZE]
        is_mac_valid = hmac.compare_digest(auth_tag, expected_tag)

        if strict and not is_mac_valid:
            flag = raw_key_package[0]
            if flag in (FLAG_PBKDF2, FLAG_SCRYPT, FLAG_DOUBLE_CASCADE):
                raise ValueError("Contraseña incorrecta o mensaje adulterado.")
            else:
                raise ValueError("Fallo de integridad HMAC o mensaje corrupto.")

        flag = raw_key_package[0]
        if flag in (FLAG_DOUBLE_DIRECT, FLAG_DOUBLE_CASCADE):
            inner_ks = _generate_keystream(key_bytes, nonce_bytes, len(ciphertext_bytes))
            inner_blob = _xor_bytes(ciphertext_bytes, inner_ks)
            plaintext_bytes = b""
            if len(inner_blob) >= 2:
                pkg1_len = int.from_bytes(inner_blob[:2], 'big')
                if 2 + pkg1_len + NONCE_SIZE + TAG_SIZE <= len(inner_blob):
                    offset = 2
                    raw_pkg_1 = inner_blob[offset:offset + pkg1_len]
                    offset += pkg1_len
                    nonce1 = inner_blob[offset:offset + NONCE_SIZE]
                    offset += NONCE_SIZE
                    tag1 = inner_blob[offset:offset + TAG_SIZE]
                    offset += TAG_SIZE
                    c1 = inner_blob[offset:]

                    k1 = _unwrap_key_from_package(raw_pkg_1, password, nonce1, c1, tag1, tolerant=True)
                    if strict:
                        auth_k1 = _derive_auth_key(k1)
                        expected_tag_1 = hmac.new(
                            auth_k1, raw_pkg_1 + nonce1 + c1, hashlib.sha256
                        ).digest()[:TAG_SIZE]
                        if not hmac.compare_digest(tag1, expected_tag_1):
                            raise ValueError("Fallo de integridad HMAC en capa interna.")
                    ks1 = _generate_keystream(k1, nonce1, len(c1))
                    plaintext_bytes = _xor_bytes(c1, ks1)
                else:
                    plaintext_bytes = inner_blob[2:]
            else:
                plaintext_bytes = inner_blob

            plaintext = plaintext_bytes.decode('utf-8', errors='replace')
            if not is_mac_valid and flag == FLAG_DOUBLE_CASCADE:
                if not _is_mostly_text(plaintext):
                    raise ValueError("Contraseña incorrecta o mensaje no recuperable.")
            return plaintext
        else:
            keystream = _generate_keystream(key_bytes, nonce_bytes, len(ciphertext_bytes))
            plaintext_bytes = _xor_bytes(ciphertext_bytes, keystream)
            plaintext = plaintext_bytes.decode('utf-8', errors='replace')
            if not is_mac_valid and flag in (FLAG_PBKDF2, FLAG_SCRYPT):
                if not _is_mostly_text(plaintext):
                    raise ValueError("Contraseña incorrecta o mensaje no recuperable.")
            return plaintext


    # Detectar presencia de alguno de los separadores definidos
    found_sep = None
    for sep in SEPARATORS:
        if sep in cleaned:
            found_sep = sep
            break

    if found_sep:
        parts = cleaned.split(found_sep, 1)
        if len(parts) != 2:
            raise ValueError("Formato inválido: el token no contiene dos secciones válidas.")

        obf_key, obf_payload = parts

        # 1. Desofuscar Payload
        payload_hex = _deobfuscate_byte_hex(obf_payload)
        payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""
        if len(payload_bytes) < (NONCE_SIZE + TAG_SIZE):
            if strict:
                raise ValueError("Mensaje cifrado corrupto o demasiado corto.")
            payload_bytes = payload_bytes.ljust(NONCE_SIZE + TAG_SIZE, b"\x00")

        nonce_bytes = payload_bytes[:NONCE_SIZE].ljust(NONCE_SIZE, b"\x00")[:NONCE_SIZE]
        auth_tag = payload_bytes[NONCE_SIZE:NONCE_SIZE + TAG_SIZE].ljust(TAG_SIZE, b"\x00")[:TAG_SIZE]
        ciphertext_bytes = payload_bytes[NONCE_SIZE + TAG_SIZE:]

        # 2. Desofuscar y Desenmascarar Clave
        masked_key_hex = _deobfuscate_byte_hex(obf_key)
        if not masked_key_hex:
            raise ValueError("No se pudo extraer la sección de clave del token.")
        masked_key_package = bytes.fromhex(masked_key_hex)

        mask = _generate_keystream(nonce_bytes, b"ENCRYPTORX_KEY_MASK", len(masked_key_package))
        raw_key_package = _xor_bytes(masked_key_package, mask)

        key_bytes = _unwrap_key_from_package(
            raw_key_package, password, nonce_bytes, ciphertext_bytes, auth_tag, tolerant=True
        )

        # 3. Verificar Integridad HMAC-SHA256
        auth_key = _derive_auth_key(key_bytes)
        expected_tag = hmac.new(
            auth_key,
            raw_key_package + nonce_bytes + ciphertext_bytes,
            hashlib.sha256
        ).digest()[:TAG_SIZE]
        is_mac_valid = hmac.compare_digest(auth_tag, expected_tag)

        if strict and not is_mac_valid:
            flag = raw_key_package[0]
            if flag in (FLAG_PBKDF2, FLAG_SCRYPT, FLAG_DOUBLE_CASCADE):
                raise ValueError("Contraseña incorrecta o mensaje adulterado.")
            else:
                raise ValueError("Fallo de integridad: el mensaje cifrado ha sido alterado o está corrupto.")

        flag = raw_key_package[0]
        if flag in (FLAG_DOUBLE_DIRECT, FLAG_DOUBLE_CASCADE):
            inner_ks = _generate_keystream(key_bytes, nonce_bytes, len(ciphertext_bytes))
            inner_blob = _xor_bytes(ciphertext_bytes, inner_ks)
            plaintext_bytes = b""
            if len(inner_blob) >= 2:
                pkg1_len = int.from_bytes(inner_blob[:2], 'big')
                if 2 + pkg1_len + NONCE_SIZE + TAG_SIZE <= len(inner_blob):
                    offset = 2
                    raw_pkg_1 = inner_blob[offset:offset + pkg1_len]
                    offset += pkg1_len
                    nonce1 = inner_blob[offset:offset + NONCE_SIZE]
                    offset += NONCE_SIZE
                    tag1 = inner_blob[offset:offset + TAG_SIZE]
                    offset += TAG_SIZE
                    c1 = inner_blob[offset:]

                    k1 = _unwrap_key_from_package(raw_pkg_1, password, nonce1, c1, tag1, tolerant=True)
                    if strict:
                        auth_k1 = _derive_auth_key(k1)
                        expected_tag_1 = hmac.new(auth_k1, raw_pkg_1 + nonce1 + c1, hashlib.sha256).digest()[:TAG_SIZE]
                        if not hmac.compare_digest(tag1, expected_tag_1):
                            raise ValueError("Fallo de integridad HMAC en capa interna.")
                    ks1 = _generate_keystream(k1, nonce1, len(c1))
                    plaintext_bytes = _xor_bytes(c1, ks1)
                else:
                    plaintext_bytes = inner_blob[2:]
            else:
                plaintext_bytes = inner_blob

            plaintext = plaintext_bytes.decode('utf-8', errors='replace')
            if not is_mac_valid and flag in (FLAG_PBKDF2, FLAG_SCRYPT, FLAG_DOUBLE_CASCADE):
                if not _is_mostly_text(plaintext):
                    raise ValueError("Contraseña incorrecta o mensaje no recuperable.")
            return plaintext
        else:
            keystream = _generate_keystream(key_bytes, nonce_bytes, len(ciphertext_bytes))
            plaintext_bytes = _xor_bytes(ciphertext_bytes, keystream)
            plaintext = plaintext_bytes.decode('utf-8', errors='replace')
            if not is_mac_valid and flag in (FLAG_PBKDF2, FLAG_SCRYPT):
                if not _is_mostly_text(plaintext):
                    raise ValueError("Contraseña incorrecta o mensaje no recuperable.")
            return plaintext


    else:
        # Fallback para Base64 tradicional
        try:
            raw = base64.urlsafe_b64decode(cleaned)
            if len(raw) < NONCE_SIZE:
                raise ValueError("Dato Base64 demasiado corto.")
            # Si se pasó contraseña, derivar clave fija
            if password:
                fallback_key = hashlib.sha256(password.encode('utf-8')).digest()
            else:
                fallback_key = hashlib.sha256(b"ENCRYPTORX_DEFAULT_KEY_FALLBACK").digest()
            nonce = raw[:NONCE_SIZE]
            cipher = raw[NONCE_SIZE:]
            ks = _generate_keystream(fallback_key, nonce, len(cipher))
            return _xor_bytes(cipher, ks).decode('utf-8')
        except Exception as e:
            raise ValueError("Token no reconocido o formato Base64 inválido.") from e

# ---------------------------------------------------------------------------
# Cifrado y Descifrado de Archivos
# ---------------------------------------------------------------------------

def encrypt_file(
    file_path: str | Path,
    output_path: Optional[str | Path] = None,
    password: Optional[str] = None
) -> Path:
    """
    Cifra un archivo completo protegiendo su integridad con HMAC.
    
    Retorna:
        Path del archivo cifrado resultante (.enc).
    """
    src = Path(file_path)
    if not src.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {src}")
    if src.stat().st_size > 500 * 1024 * 1024:
        raise ValueError("El archivo supera el límite de seguridad de 500 MB.")

    dest = Path(output_path) if output_path else Path(f"{src}.enc")
    data = src.read_bytes()

    key_bytes = secrets.token_bytes(KEY_SIZE)
    nonce_bytes = secrets.token_bytes(NONCE_SIZE)

    if password:
        salt = secrets.token_bytes(SALT_SIZE)
        wrapping_key = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
        )
        enc_key = _xor_bytes(key_bytes, _generate_keystream(wrapping_key, salt, KEY_SIZE))
        header = b"ENCX\x02\x01" + salt + enc_key
    else:
        header = b"ENCX\x02\x00" + key_bytes

    keystream = _generate_keystream(key_bytes, nonce_bytes, len(data))
    ciphertext = _xor_bytes(data, keystream)

    auth_key = _derive_auth_key(key_bytes)
    auth_tag = hmac.new(auth_key, header + nonce_bytes + ciphertext, hashlib.sha256).digest()[:TAG_SIZE]

    final_payload = header + nonce_bytes + auth_tag + ciphertext
    dest.write_bytes(final_payload)
    return dest

def decrypt_file(
    file_path: str | Path,
    output_path: Optional[str | Path] = None,
    password: Optional[str] = None
) -> Path:
    """
    Descifra un archivo cifrado (.enc) validando su integridad.
    
    Retorna:
        Path del archivo descifrado resultante.
    """
    src = Path(file_path)
    if not src.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {src}")

    data = src.read_bytes()
    if not data.startswith(b"ENCX\x02"):
        raise ValueError("El archivo no tiene la cabecera válida de EncryptorX.")

    flag = data[5]
    offset = 6

    if flag == 0x01:
        if not password:
            raise ValueError("Este archivo está protegido con contraseña.")
        salt = data[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        enc_key = data[offset:offset + KEY_SIZE]
        offset += KEY_SIZE
        wrapping_key = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
        )
        key_bytes = _xor_bytes(enc_key, _generate_keystream(wrapping_key, salt, KEY_SIZE))
    else:
        key_bytes = data[offset:offset + KEY_SIZE]
        offset += KEY_SIZE

    nonce_bytes = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    auth_tag = data[offset:offset + TAG_SIZE]
    offset += TAG_SIZE
    ciphertext = data[offset:]

    header_len = 6 + (SALT_SIZE + KEY_SIZE if flag == 0x01 else KEY_SIZE)
    header = data[:header_len]
    auth_key = _derive_auth_key(key_bytes)
    expected_tag = hmac.new(auth_key, header + nonce_bytes + ciphertext, hashlib.sha256).digest()[:TAG_SIZE]

    if not hmac.compare_digest(auth_tag, expected_tag):
        raise ValueError("Fallo de autenticación: contraseña incorrecta o archivo alterado.")

    keystream = _generate_keystream(key_bytes, nonce_bytes, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, keystream)

    if output_path:
        dest = Path(output_path)
    else:
        base_name = str(src)
        if base_name.endswith(".enc"):
            dest = Path(base_name[:-4])
        else:
            dest = Path(f"{base_name}.dec")

    # Evitar sobreescribir si ya existe
    if dest.exists():
        stem, ext = dest.stem, dest.suffix
        counter = 1
        while dest.exists():
            dest = dest.parent / f"{stem}.dec({counter}){ext}"
            counter += 1

    dest.write_bytes(plaintext)
    return dest

# ---------------------------------------------------------------------------
# Utilidades Rápidas (Base64 & Generador de Claves)
# ---------------------------------------------------------------------------

def base64_encode(text: str) -> str:
    """Codifica un string a Base64 estándar."""
    if not text:
        return ""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decode(b64_str: str) -> str:
    """Decodifica un string Base64 a texto claro."""
    if not b64_str:
        return ""
    try:
        return base64.b64decode(b64_str).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error al decodificar Base64: {e}")

def generate_random_password(length: int = 24) -> str:
    """Genera una contraseña aleatoria de alta entropía."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------------------------------------------------------------------------
# Interfaz Gráfica de Usuario Moderna (Tkinter)
# ---------------------------------------------------------------------------

def launch_gui():
    """Lanza la interfaz gráfica moderna de EncryptorX."""
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    class ModernEncryptorGUI(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"{__app_name__} v{__version__} — Cifrador de Flujo")
            self.geometry("900x700")
            self.minsize(750, 550)

            # Paleta de colores Dark Modern (Tokyo Night / Catppuccin)
            self.colors = {
                "bg": "#181825",          # Fondo de ventana
                "card": "#1E1E2E",        # Fondo de paneles
                "input_bg": "#11111B",    # Cajas de texto
                "fg": "#CDD6F4",          # Texto normal
                "fg_dim": "#A6ADC8",      # Texto secundario
                "accent": "#89DCEB",      # Acento Cyan brillante
                "accent_hover": "#74C7EC",# Hover Cyan
                "primary": "#CBA6F7",     # Botón primario Lavanda
                "primary_hover": "#B4BEFE",
                "danger": "#F38BA8",      # Rojo pastel para errores
                "success": "#A6E3A1",     # Verde pastel
                "border": "#313244",      # Bordes
            }

            self.configure(bg=self.colors["bg"])
            self.setup_styles()
            self.build_ui()

        def setup_styles(self):
            style = ttk.Style(self)
            style.theme_use("clam")

            style.configure(".", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 10))
            style.configure("TFrame", background=self.colors["bg"])
            style.configure("Card.TFrame", background=self.colors["card"])

            style.configure(
                "TNotebook",
                background=self.colors["bg"],
                borderwidth=0,
                tabmargins=[10, 5, 10, 0]
            )
            style.configure(
                "TNotebook.Tab",
                background=self.colors["card"],
                foreground=self.colors["fg_dim"],
                padding=[18, 8],
                font=("Segoe UI", 11, "bold"),
                borderwidth=0
            )
            style.map(
                "TNotebook.Tab",
                background=[("selected", self.colors["primary"])],
                foreground=[("selected", "#11111B")]
            )

            # Botones primarios y secundarios
            style.configure(
                "Primary.TButton",
                background=self.colors["primary"],
                foreground="#11111B",
                font=("Segoe UI", 10, "bold"),
                padding=[14, 8],
                borderwidth=0
            )
            style.map("Primary.TButton", background=[("active", self.colors["primary_hover"])])

            style.configure(
                "Action.TButton",
                background=self.colors["accent"],
                foreground="#11111B",
                font=("Segoe UI", 10, "bold"),
                padding=[14, 8],
                borderwidth=0
            )
            style.map("Action.TButton", background=[("active", self.colors["accent_hover"])])

            style.configure(
                "Outline.TButton",
                background=self.colors["border"],
                foreground=self.colors["fg"],
                font=("Segoe UI", 9),
                padding=[10, 6],
                borderwidth=0
            )
            style.map("Outline.TButton", background=[("active", self.colors["card"])])

        def build_ui(self):
            # Barra de encabezado
            header = tk.Frame(self, bg=self.colors["card"], height=60)
            header.pack(fill="x", side="top")

            title_lbl = tk.Label(
                header,
                text=f"🔒 {__app_name__}",
                font=("Segoe UI", 16, "bold"),
                bg=self.colors["card"],
                fg=self.colors["accent"]
            )
            title_lbl.pack(side="left", padx=20, pady=12)

            sub_lbl = tk.Label(
                header,
                text="Cifrador de Flujo Null-Obfuscated con Clave Integrada y HMAC",
                font=("Segoe UI", 10),
                bg=self.colors["card"],
                fg=self.colors["fg_dim"]
            )
            sub_lbl.pack(side="left", padx=5, pady=15)

            badge = tk.Label(
                header,
                text=f"v{__version__}",
                font=("Segoe UI", 9, "bold"),
                bg=self.colors["border"],
                fg=self.colors["fg"],
                padx=8,
                pady=2
            )
            badge.pack(side="right", padx=20, pady=15)

            # Pestañas
            self.notebook = ttk.Notebook(self)
            self.notebook.pack(expand=True, fill="both", padx=15, pady=10)

            self.tab_text = ttk.Frame(self.notebook, padding=12)
            self.tab_files = ttk.Frame(self.notebook, padding=12)
            self.tab_tools = ttk.Frame(self.notebook, padding=12)

            self.notebook.add(self.tab_text, text="  📝 Texto Cifrado  ")
            self.notebook.add(self.tab_files, text="  📂 Cifrar Archivos  ")
            self.notebook.add(self.tab_tools, text="  ⚙️ Herramientas  ")

            self.build_text_tab()
            self.build_files_tab()
            self.build_tools_tab()

            # Barra de estado inferior
            self.status_bar = tk.Label(
                self,
                text="Listo para cifrar o descifrar.",
                font=("Segoe UI", 9),
                bg=self.colors["card"],
                fg=self.colors["fg_dim"],
                anchor="w",
                padx=15,
                pady=6
            )
            self.status_bar.pack(fill="x", side="bottom")

        def build_text_tab(self):
            # Barra superior de opciones (Separador y Contraseña opcional)
            opts_card = tk.Frame(self.tab_text, bg=self.colors["card"], padx=10, pady=8)
            opts_card.pack(fill="x", pady=(0, 10))

            tk.Label(
                opts_card, text="Separador:", font=("Segoe UI", 9, "bold"),
                bg=self.colors["card"], fg=self.colors["fg"]
            ).pack(side="left", padx=5)

            self.sep_var = tk.StringVar(value="$")
            sep_menu = ttk.Combobox(
                opts_card, textvariable=self.sep_var, values=SEPARATORS, width=4, state="readonly"
            )
            sep_menu.pack(side="left", padx=5)

            tk.Label(
                opts_card, text="Contraseña / PIN (Opcional):", font=("Segoe UI", 9, "bold"),
                bg=self.colors["card"], fg=self.colors["fg"]
            ).pack(side="left", padx=(25, 5))

            self.pass_entry = tk.Entry(
                opts_card, font=("Segoe UI", 10), bg=self.colors["input_bg"],
                fg=self.colors["fg"], insertbackground=self.colors["accent"],
                show="•", width=25, relief="flat"
            )
            self.pass_entry.pack(side="left", padx=5)

            self.show_pass_btn = tk.Button(
                opts_card, text="👁", font=("Segoe UI", 9), bg=self.colors["border"],
                fg=self.colors["fg"], relief="flat", padx=6, command=self.toggle_password_visibility
            )
            self.show_pass_btn.pack(side="left", padx=3)

            # Área de Entrada
            in_header = tk.Frame(self.tab_text, bg=self.colors["bg"])
            in_header.pack(fill="x", pady=(5, 2))
            tk.Label(
                in_header, text="Mensaje o Token Cifrado (Entrada):", font=("Segoe UI", 10, "bold"),
                bg=self.colors["bg"], fg=self.colors["accent"]
            ).pack(side="left")

            self.in_char_lbl = tk.Label(
                in_header, text="0 caracteres", font=("Segoe UI", 9),
                bg=self.colors["bg"], fg=self.colors["fg_dim"]
            )
            self.in_char_lbl.pack(side="right")

            self.txt_input = tk.Text(
                self.tab_text, height=7, bg=self.colors["input_bg"], fg=self.colors["fg"],
                insertbackground=self.colors["accent"], font=("Consolas", 10),
                relief="flat", padx=10, pady=8
            )
            self.txt_input.pack(fill="both", expand=True, pady=(0, 8))
            self.txt_input.bind("<KeyRelease>", self.update_char_counts)

            # Botones de Acción
            btn_bar = tk.Frame(self.tab_text, bg=self.colors["bg"])
            btn_bar.pack(fill="x", pady=6)

            ttk.Button(
                btn_bar, text="🔒 Cifrar Texto", style="Action.TButton",
                command=self.handle_encrypt_text
            ).pack(side="left", padx=5)

            ttk.Button(
                btn_bar, text="🔓 Descifrar Texto", style="Primary.TButton",
                command=self.handle_decrypt_text
            ).pack(side="left", padx=5)

            ttk.Button(
                btn_bar, text="📋 Pegar", style="Outline.TButton",
                command=self.handle_paste_input
            ).pack(side="left", padx=5)

            ttk.Button(
                btn_bar, text="🗑️ Limpiar Todo", style="Outline.TButton",
                command=self.handle_clear_fields
            ).pack(side="left", padx=5)

            ttk.Button(
                btn_bar, text="⇄ Intercambiar", style="Outline.TButton",
                command=self.handle_swap_fields
            ).pack(side="left", padx=5)

            # Área de Salida
            out_header = tk.Frame(self.tab_text, bg=self.colors["bg"])
            out_header.pack(fill="x", pady=(8, 2))
            tk.Label(
                out_header, text="Resultado (Salida):", font=("Segoe UI", 10, "bold"),
                bg=self.colors["bg"], fg=self.colors["primary"]
            ).pack(side="left")

            self.out_char_lbl = tk.Label(
                out_header, text="0 caracteres", font=("Segoe UI", 9),
                bg=self.colors["bg"], fg=self.colors["fg_dim"]
            )
            self.out_char_lbl.pack(side="right")

            self.copy_btn = tk.Button(
                out_header, text="📄 Copiar al Portapapeles", font=("Segoe UI", 9, "bold"),
                bg=self.colors["border"], fg=self.colors["accent"], relief="flat",
                padx=8, pady=2, command=self.handle_copy_output
            )
            self.copy_btn.pack(side="right", padx=10)

            self.txt_output = tk.Text(
                self.tab_text, height=7, bg=self.colors["input_bg"], fg=self.colors["fg"],
                insertbackground=self.colors["accent"], font=("Consolas", 10),
                relief="flat", padx=10, pady=8
            )
            self.txt_output.pack(fill="both", expand=True, pady=(0, 5))

        def build_files_tab(self):
            card = tk.Frame(self.tab_files, bg=self.colors["card"], padx=20, pady=20)
            card.pack(fill="both", expand=True)

            tk.Label(
                card, text="Cifrado y Descifrado Seguro de Archivos",
                font=("Segoe UI", 13, "bold"), bg=self.colors["card"], fg=self.colors["accent"]
            ).pack(anchor="w", pady=(0, 8))

            tk.Label(
                card,
                text="Protege cualquier tipo de archivo (.pdf, .zip, .mp4, .png, etc.) hasta 500 MB con HMAC anti-tamper.",
                font=("Segoe UI", 10), bg=self.colors["card"], fg=self.colors["fg_dim"]
            ).pack(anchor="w", pady=(0, 20))

            # Selector de archivo
            f_frame = tk.Frame(card, bg=self.colors["card"])
            f_frame.pack(fill="x", pady=10)

            self.selected_file_path = tk.StringVar(value="Ningún archivo seleccionado")
            f_entry = tk.Entry(
                f_frame, textvariable=self.selected_file_path, font=("Segoe UI", 10),
                bg=self.colors["input_bg"], fg=self.colors["fg_dim"],
                state="readonly", relief="flat", width=55
            )
            f_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=6)

            ttk.Button(
                f_frame, text="Examinar...", style="Outline.TButton",
                command=self.handle_browse_file
            ).pack(side="left")

            # Contraseña para archivos
            pass_f_frame = tk.Frame(card, bg=self.colors["card"])
            pass_f_frame.pack(fill="x", pady=15)

            tk.Label(
                pass_f_frame, text="Contraseña del Archivo (Opcional):", font=("Segoe UI", 10, "bold"),
                bg=self.colors["card"], fg=self.colors["fg"]
            ).pack(side="left", padx=(0, 10))

            self.file_pass_entry = tk.Entry(
                pass_f_frame, font=("Segoe UI", 10), bg=self.colors["input_bg"],
                fg=self.colors["fg"], insertbackground=self.colors["accent"],
                show="•", width=30, relief="flat"
            )
            self.file_pass_entry.pack(side="left", ipady=4)

            # Botones de acción de archivos
            btn_f_frame = tk.Frame(card, bg=self.colors["card"])
            btn_f_frame.pack(fill="x", pady=25)

            ttk.Button(
                btn_f_frame, text="🔒 Cifrar Archivo (.enc)", style="Action.TButton",
                command=self.handle_encrypt_file
            ).pack(side="left", padx=(0, 10))

            ttk.Button(
                btn_f_frame, text="🔓 Descifrar Archivo", style="Primary.TButton",
                command=self.handle_decrypt_file
            ).pack(side="left")

        def build_tools_tab(self):
            card = tk.Frame(self.tab_tools, bg=self.colors["card"], padx=20, pady=20)
            card.pack(fill="both", expand=True)

            tk.Label(
                card, text="Generador de Contraseñas y Claves Criptográficas",
                font=("Segoe UI", 12, "bold"), bg=self.colors["card"], fg=self.colors["accent"]
            ).pack(anchor="w", pady=(0, 10))

            # Generador
            gen_frame = tk.Frame(card, bg=self.colors["card"])
            gen_frame.pack(fill="x", pady=5)

            self.gen_pass_var = tk.StringVar()
            tk.Entry(
                gen_frame, textvariable=self.gen_pass_var, font=("Consolas", 11),
                bg=self.colors["input_bg"], fg=self.colors["accent"],
                relief="flat", width=40, state="readonly"
            ).pack(side="left", padx=(0, 10), ipady=5)

            ttk.Button(
                gen_frame, text="⚡ Generar Contraseña (24 caracteres)", style="Action.TButton",
                command=lambda: self.gen_pass_var.set(generate_random_password(24))
            ).pack(side="left", padx=5)

            ttk.Button(
                gen_frame, text="📋 Copiar", style="Outline.TButton",
                command=lambda: self.copy_to_clipboard(self.gen_pass_var.get())
            ).pack(side="left", padx=5)

            # Divisor
            tk.Frame(card, height=1, bg=self.colors["border"]).pack(fill="x", pady=20)

            # Base64 directo
            tk.Label(
                card, text="Codificador / Decodificador Rápido Base64",
                font=("Segoe UI", 12, "bold"), bg=self.colors["card"], fg=self.colors["primary"]
            ).pack(anchor="w", pady=(0, 10))

            b64_btn_frame = tk.Frame(card, bg=self.colors["card"])
            b64_btn_frame.pack(fill="x", pady=5)

            ttk.Button(
                b64_btn_frame, text="Base64 Encode (Texto de Entrada)", style="Outline.TButton",
                command=self.handle_base64_encode
            ).pack(side="left", padx=(0, 10))

            ttk.Button(
                b64_btn_frame, text="Base64 Decode (Texto de Entrada)", style="Outline.TButton",
                command=self.handle_base64_decode
            ).pack(side="left")

        # --- Manejadores de Eventos de la Interfaz ---
        def toggle_password_visibility(self):
            if self.pass_entry.cget("show") == "•":
                self.pass_entry.configure(show="")
                self.show_pass_btn.configure(text="Ocultar")
            else:
                self.pass_entry.configure(show="•")
                self.show_pass_btn.configure(text="Mostrar")

        def update_char_counts(self, _event=None):
            in_len = len(self.txt_input.get("1.0", tk.END).strip())
            self.in_char_lbl.configure(text=f"{in_len:,} caracteres")

        def handle_encrypt_text(self):
            content = self.txt_input.get("1.0", tk.END).strip()
            if not content:
                self.set_status("Por favor ingrese un texto a cifrar.", error=True)
                return
            password = self.pass_entry.get().strip() or None
            delimiter = self.sep_var.get()

            try:
                result = encrypt(content, password=password, delimiter=delimiter)
                self.txt_output.delete("1.0", tk.END)
                self.txt_output.insert(tk.END, result)
                self.out_char_lbl.configure(text=f"{len(result):,} caracteres")
                mode_desc = "con contraseña PBKDF2" if password else "auto-descifrable"
                self.set_status(f"¡Texto cifrado exitosamente ({mode_desc}) con separador '{delimiter}'!")
            except Exception as e:
                self.set_status(f"Error al cifrar: {e}", error=True)

        def handle_decrypt_text(self):
            content = self.txt_input.get("1.0", tk.END).strip()
            if not content:
                self.set_status("Por favor ingrese el token a descifrar.", error=True)
                return
            password = self.pass_entry.get().strip() or None

            try:
                result = decrypt(content, password=password)
                self.txt_output.delete("1.0", tk.END)
                self.txt_output.insert(tk.END, result)
                self.out_char_lbl.configure(text=f"{len(result):,} caracteres")
                self.set_status("¡Texto descifrado exitosamente!")
            except Exception as e:
                self.set_status(f"Error al descifrar: {e}", error=True)
                messagebox.showerror("Error de Descifrado", str(e))

        def handle_copy_output(self):
            out_text = self.txt_output.get("1.0", tk.END).strip()
            if out_text:
                self.copy_to_clipboard(out_text)
                self.copy_btn.configure(text="¡Copiado!", bg=self.colors["success"], fg="#11111B")
                self.after(2000, lambda: self.copy_btn.configure(
                    text="Copiar al Portapapeles", bg=self.colors["border"], fg=self.colors["accent"]
                ))
                self.set_status("Texto copiado al portapapeles.")


        def copy_to_clipboard(self, text: str):
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
                self.update()

        def handle_paste_input(self):
            try:
                clip = self.clipboard_get()
                self.txt_input.delete("1.0", tk.END)
                self.txt_input.insert(tk.END, clip)
                self.update_char_counts()
                self.set_status("Texto pegado desde el portapapeles.")
            except Exception:
                self.set_status("El portapapeles está vacío o no contiene texto.", error=True)

        def handle_clear_fields(self):
            self.txt_input.delete("1.0", tk.END)
            self.txt_output.delete("1.0", tk.END)
            self.pass_entry.delete(0, tk.END)
            self.update_char_counts()
            self.out_char_lbl.configure(text="0 caracteres")
            self.set_status("Campos limpiados.")

        def handle_swap_fields(self):
            in_text = self.txt_input.get("1.0", tk.END).strip()
            out_text = self.txt_output.get("1.0", tk.END).strip()
            self.txt_input.delete("1.0", tk.END)
            self.txt_output.delete("1.0", tk.END)
            self.txt_input.insert(tk.END, out_text)
            self.txt_output.insert(tk.END, in_text)
            self.update_char_counts()
            self.out_char_lbl.configure(text=f"{len(in_text):,} caracteres")
            self.set_status("Campos intercambiados.")

        def handle_browse_file(self):
            path = filedialog.askopenfilename()
            if path:
                self.selected_file_path.set(path)
                self.set_status(f"Archivo seleccionado: {Path(path).name}")

        def handle_encrypt_file(self):
            path = self.selected_file_path.get()
            if not path or path == "Ningún archivo seleccionado":
                self.set_status("Seleccione un archivo primero.", error=True)
                return
            password = self.file_pass_entry.get().strip() or None
            try:
                dest = encrypt_file(path, password=password)
                self.set_status(f"¡Archivo cifrado guardado en: {dest.name}!")
                messagebox.showinfo("Éxito", f"Archivo cifrado exitosamente en:\n{dest}")
            except Exception as e:
                self.set_status(f"Error al cifrar archivo: {e}", error=True)
                messagebox.showerror("Error", str(e))

        def handle_decrypt_file(self):
            path = self.selected_file_path.get()
            if not path or path == "Ningún archivo seleccionado":
                self.set_status("Seleccione un archivo primero.", error=True)
                return
            password = self.file_pass_entry.get().strip() or None
            try:
                dest = decrypt_file(path, password=password)
                self.set_status(f"¡Archivo descifrado guardado en: {dest.name}!")
                messagebox.showinfo("Éxito", f"Archivo descifrado exitosamente en:\n{dest}")
            except Exception as e:
                self.set_status(f"Error al descifrar archivo: {e}", error=True)
                messagebox.showerror("Error", str(e))

        def handle_base64_encode(self):
            content = self.txt_input.get("1.0", tk.END).strip()
            if content:
                enc = base64_encode(content)
                self.txt_output.delete("1.0", tk.END)
                self.txt_output.insert(tk.END, enc)
                self.set_status("Texto codificado en Base64.")

        def handle_base64_decode(self):
            content = self.txt_input.get("1.0", tk.END).strip()
            if content:
                try:
                    dec = base64_decode(content)
                    self.txt_output.delete("1.0", tk.END)
                    self.txt_output.insert(tk.END, dec)
                    self.set_status("Texto decodificado de Base64.")
                except Exception as e:
                    self.set_status(f"Error Base64: {e}", error=True)

        def set_status(self, message: str, error: bool = False):
            self.status_bar.configure(
                text=f" {'[ERROR] ' if error else '[INFO] '} {message}",
                fg=self.colors["danger"] if error else self.colors["success"]
            )

    app = ModernEncryptorGUI()
    app.mainloop()

# ---------------------------------------------------------------------------
# Interfaz de Línea de Comandos (CLI)
# ---------------------------------------------------------------------------

def run_cli():
    """Manejador de la interfaz de línea de comandos."""
    parser = argparse.ArgumentParser(
        description=f"{__app_name__} v{__version__} - Enterprise Cryptographic Suite & Null-Obfuscated Cipher"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", help="Cifrar una cadena de texto")
    group.add_argument("-d", "--decrypt", help="Descifrar una cadena de texto")
    group.add_argument("--encrypt-file", help="Ruta de un archivo a cifrar")
    group.add_argument("--decrypt-file", help="Ruta de un archivo a descifrar")
    group.add_argument("--create-vault", help="Empaquetar y cifrar un directorio en un contenedor .vault")
    group.add_argument("--extract-vault", help="Descifrar y extraer un contenedor .vault")
    group.add_argument("--inspect-vault", help="Inspeccionar el manifiesto de un contenedor .vault sin extraerlo")
    group.add_argument("--split-secret", help="Dividir un secreto en fragmentos Shamir (k, n)")
    group.add_argument("--combine-shares", nargs="+", help="Reconstruir un secreto a partir de fragmentos Shamir")
    group.add_argument("--audit-entropy", help="Auditar calidad estadística y entropía de un archivo (FIPS 140-2)")
    group.add_argument("--generate-keyfile", help="Generar un keyfile criptográfico de 256 bits para MFA")
    group.add_argument("--gui", action="store_true", help="Lanzar la interfaz gráfica de usuario")

    parser.add_argument("-p", "--password", help="Contraseña opcional para blindar el cifrado")
    parser.add_argument("--keyfile", help="Ruta del keyfile para autenticación multi-factor (MFA)")
    parser.add_argument("-k", "--threshold", type=int, default=3, help="Umbral de fragmentos requeridos (k) para Shamir (def: 3)")
    parser.add_argument("-n", "--shares", type=int, default=5, help="Total de fragmentos a generar (n) para Shamir (def: 5)")
    parser.add_argument("--cipher", default="chacha20", choices=["chacha20", "aes"], help="Algoritmo de cifrado: chacha20 (ChaCha20-Poly1305) o aes (AES-256-GCM)")
    parser.add_argument(
        "-s", "--separator", default=DEFAULT_SEPARATOR, choices=SEPARATORS,
        help=f"Delimitador de secciones (por defecto: {DEFAULT_SEPARATOR})"
    )
    parser.add_argument("-o", "--output", help="Ruta de salida para archivos o directorios")

    args = parser.parse_args()

    if args.gui or len(sys.argv) == 1:
        launch_gui()
    elif args.encrypt:
        print(encrypt(args.encrypt, password=args.password, delimiter=args.separator))
    elif args.decrypt:
        try:
            print(decrypt(args.decrypt, password=args.password))
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            sys.exit(1)
    elif args.encrypt_file:
        try:
            dest = encrypt_file(args.encrypt_file, output_path=args.output, password=args.password)
            print(f"Archivo cifrado: {dest}")
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            sys.exit(1)
    elif args.decrypt_file:
        try:
            dest = decrypt_file(args.decrypt_file, output_path=args.output, password=args.password)
            print(f"Archivo descifrado: {dest}")
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            sys.exit(1)
    elif args.create_vault:
        try:
            import encryptorx
            out_vault = args.output or (args.create_vault.rstrip("/\\") + ".vault")
            res = encryptorx.create_vault(
                source_dir=args.create_vault,
                vault_path=out_vault,
                password=args.password,
                keyfile_path=args.keyfile,
                cipher=args.cipher,
            )
            print(f"Contenedor .vault creado exitosamente: {res}")
        except Exception as e:
            sys.stderr.write(f"Error al crear vault: {e}\n")
            sys.exit(1)
    elif args.extract_vault:
        try:
            import encryptorx
            out_dir = args.output or (Path(args.extract_vault).stem + "_extracted")
            files = encryptorx.extract_vault(
                vault_path=args.extract_vault,
                output_dir=out_dir,
                password=args.password,
                keyfile_path=args.keyfile,
            )
            print(f"Vault extraido en: {out_dir} ({len(files)} archivos)")
        except Exception as e:
            sys.stderr.write(f"Error al extraer vault: {e}\n")
            sys.exit(1)
    elif args.inspect_vault:
        try:
            import encryptorx
            import json
            info = encryptorx.inspect_vault(
                vault_path=args.inspect_vault,
                password=args.password,
                keyfile_path=args.keyfile,
            )
            print(json.dumps(info, indent=2))
        except Exception as e:
            sys.stderr.write(f"Error al inspeccionar vault: {e}\n")
            sys.exit(1)
    elif args.split_secret:
        try:
            import encryptorx
            shares = encryptorx.split_secret(args.split_secret, k=args.threshold, n=args.shares)
            print(f"Dividiendo secreto con esquema ({args.threshold}, {args.shares}):")
            for idx, share in enumerate(shares, 1):
                print(f"  Share {idx}: {share}")
        except Exception as e:
            sys.stderr.write(f"Error al dividir secreto: {e}\n")
            sys.exit(1)
    elif args.combine_shares:
        try:
            import encryptorx
            recovered = encryptorx.combine_shares(args.combine_shares)
            try:
                print("Secreto recuperado:", recovered.decode("utf-8"))
            except UnicodeDecodeError:
                print("Secreto recuperado (hex):", recovered.hex())
        except Exception as e:
            sys.stderr.write(f"Error al reconstruir secreto: {e}\n")
            sys.exit(1)
    elif args.audit_entropy:
        try:
            import encryptorx
            import json
            p = Path(args.audit_entropy)
            data = p.read_bytes()
            report = encryptorx.audit_randomness(data)
            print(json.dumps(report, indent=2))
        except Exception as e:
            sys.stderr.write(f"Error al auditar entropia: {e}\n")
            sys.exit(1)
    elif args.generate_keyfile:
        try:
            import encryptorx
            out_file = encryptorx.generate_keyfile(args.generate_keyfile)
            print(f"Keyfile criptografico generado: {out_file}")
        except Exception as e:
            sys.stderr.write(f"Error al generar keyfile: {e}\n")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Entrada Principal
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_cli()
