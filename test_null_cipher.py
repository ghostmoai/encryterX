# -*- coding: utf-8 -*-
"""
Comprehensive automated tests for EncryptorX Null-Obfuscated Cipher.
Tests:
- Key and payload in the same string.
- NULL-based wrappers (NU..LL, LL..LL, n..ull, null..null) with random noise.
- Delimiters ($, %, &, #, ?).
- Various text formats (accents, emojis, multiline, symbols).
- Backward compatibility with legacy Base64 format.
- File encryption and decryption.
"""
import os
import sys
import unittest
import base64

# Add project root to sys.path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import encryption_logic

class TestNullObfuscatedCipher(unittest.TestCase):

    def setUp(self):
        self.delimiters = ['$', '%', '&', '#']

    def test_basic_encryption_decryption(self):
        text = "Hola mundo desde EncryptorX"
        for delimiter in self.delimiters:
            with self.subTest(delimiter=delimiter):
                encrypted = encryption_logic.encrypt_text(text, delimiter=delimiter)
                self.assertIn(delimiter, encrypted)
                self.assertFalse("null" in encrypted.lower())
                self.assertTrue(any(sym in encrypted for sym in ["[", "]", "{", "}", "<", ">", "~", "^", "*", "@", "!"]))
                decrypted = encryption_logic.decrypt_text(encrypted)
                self.assertEqual(decrypted, text)

    def test_empty_string(self):
        self.assertEqual(encryption_logic.encrypt_text(""), "")
        self.assertEqual(encryption_logic.decrypt_text(""), "")

    def test_special_characters_and_accents(self):
        text = "¡Atención! El niño jugó con el pingüino en la montaña: áéíóú, ÁÉÍÓÚ, ¿Por qué no?"
        for delimiter in self.delimiters:
            encrypted = encryption_logic.encrypt_text(text, delimiter=delimiter)
            decrypted = encryption_logic.decrypt_text(encrypted)
            self.assertEqual(decrypted, text)

    def test_emojis_and_symbols(self):
        text = "Seguridad total: 🔒🔑🚀💻 -> [~`!@#^*()_+-={}|[]\\:;\"'<>,./]"
        for delimiter in self.delimiters:
            encrypted = encryption_logic.encrypt_text(text, delimiter=delimiter)
            decrypted = encryption_logic.decrypt_text(encrypted)
            self.assertEqual(decrypted, text)

    def test_multiline_text(self):
        text = "Línea 1\nLínea 2 con tabulador:\tvalor\r\nLínea 3 con comillas 'simples' y \"dobles\"."
        encrypted = encryption_logic.encrypt_text(text)
        decrypted = encryption_logic.decrypt_text(encrypted)
        self.assertEqual(decrypted, text)

    def test_long_text(self):
        text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 50
        encrypted = encryption_logic.encrypt_text(text)
        decrypted = encryption_logic.decrypt_text(encrypted)
        self.assertEqual(decrypted, text)

    def test_each_message_has_unique_ephemeral_key(self):
        text = "Mensaje idéntico"
        enc1 = encryption_logic.encrypt_text(text)
        enc2 = encryption_logic.encrypt_text(text)
        self.assertNotEqual(enc1, enc2, "Dos llamadas consecutivas deben generar claves/nonces únicos")
        self.assertEqual(encryption_logic.decrypt_text(enc1), text)
        self.assertEqual(encryption_logic.decrypt_text(enc2), text)

    def test_obfuscation_patterns_presence(self):
        text = "Prueba de patrones NULL"
        encrypted = encryption_logic.encrypt_text(text)
        # Should have patterns like NU..LL, LL..LL, n..ull or null..null
        key_part, payload_part = encrypted.split('$', 1)
        self.assertTrue(len(key_part) > 100)
        self.assertTrue(len(payload_part) > 100)
        
        # Test deobfuscation
        key_hex = encryption_logic._deobfuscate_byte_hex(key_part)
        self.assertEqual(len(key_hex), 64, "La clave extraída debe tener 32 bytes (64 hex)")
        
        payload_hex = encryption_logic._deobfuscate_byte_hex(payload_part)
        self.assertTrue(len(payload_hex) >= 32, "El payload debe contener al menos 16 bytes de nonce")

    def test_legacy_base64_backward_compatibility(self):
        # Create legacy Base64 encrypted text using internal _encrypt with local CLAVE
        plain = "Mensaje en formato antiguo Base64"
        legacy_bytes = encryption_logic._encrypt(plain.encode('utf-8'), encryption_logic.CLAVE)
        legacy_b64 = base64.urlsafe_b64encode(legacy_bytes).decode('utf-8')
        
        # Must decrypt successfully via decrypt_text fallback
        recovered = encryption_logic.decrypt_text(legacy_b64)
        self.assertEqual(recovered, plain)

    def test_legacy_null_wrapper_backward_compatibility(self):
        plain = "Mensaje con envoltorios NULL heredados"
        key_bytes = os.urandom(32)
        payload_bytes = encryption_logic._encrypt(plain.encode('utf-8'), key_bytes)
        
        legacy_key_obf = "".join(f"NU{b:02x}LL" for b in key_bytes)
        legacy_payload_obf = "".join(f"null{b:02x}null" for b in payload_bytes)
        legacy_token = f"{legacy_key_obf}${legacy_payload_obf}"
        
        recovered = encryption_logic.decrypt_text(legacy_token)
        self.assertEqual(recovered, plain)

    def test_file_encryption_decryption(self):
        test_file = os.path.join(PROJECT_DIR, "test_sample.txt")
        content = b"Contenido binario o de texto para prueba de archivo 12345."
        with open(test_file, "wb") as f:
            f.write(content)
            
        try:
            enc_data = encryption_logic.encrypt_file(test_file)
            enc_file = test_file + ".enc"
            with open(enc_file, "wb") as f:
                f.write(enc_data)
                
            dec_data = encryption_logic.decrypt_file(enc_file)
            self.assertEqual(dec_data, content)
            
            if os.path.exists(enc_file):
                os.remove(enc_file)
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

if __name__ == "__main__":
    unittest.main(verbosity=2)
