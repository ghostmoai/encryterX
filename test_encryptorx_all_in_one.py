# -*- coding: utf-8 -*-
"""
Test suite for EncryptorX All-In-One module.
Tests:
- Library usage
- Null-Obfuscated Cipher with HMAC authentication
- Direct auto-decrypt mode
- Password-protected mode with PBKDF2
- Delimiters ($, %, &, #, ?)
- Anti-tampering / Integrity validation
- File encryption / decryption
- CLI execution
"""
import os
import sys
import subprocess
import unittest

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import EncryptorX

class TestEncryptorXAllInOne(unittest.TestCase):

    def setUp(self):
        self.delimiters = ['$', '%', '&', '#']

    def test_direct_mode_all_delimiters(self):
        msg = "Mensaje confidencial de prueba con tildes (áéíóú, ñ) y emojis 🚀🔒"
        for delim in self.delimiters:
            with self.subTest(delimiter=delim):
                token = EncryptorX.encrypt(msg, delimiter=delim)
                self.assertIn(delim, token)
                # Verify that no 'null' exists in the token
                self.assertFalse("null" in token.lower())
                # Verify that symbolic/numeric wrappers exist
                self.assertTrue(any(sym in token for sym in ["[", "]", "{", "}", "<", ">", "~", "^", "*", "@", "!"]))
                # Decrypt
                dec = EncryptorX.decrypt(token)
                self.assertEqual(dec, msg)

    def test_password_protected_mode(self):
        msg = "Datos protegidos por clave maestra secreta"
        pwd = "MiContraseñaSuperSegura_2026!"
        token = EncryptorX.encrypt(msg, password=pwd)

        # 1. Decrypt with correct password
        dec = EncryptorX.decrypt(token, password=pwd)
        self.assertEqual(dec, msg)

        # 2. Decrypt with wrong password must fail
        with self.assertRaises(ValueError):
            EncryptorX.decrypt(token, password="ClaveIncorrecta")

        # 3. Decrypt without password must fail
        with self.assertRaises(ValueError):
            EncryptorX.decrypt(token)

    def test_hmac_anti_tamper(self):
        msg = "Transacción bancaria de $10,000 USD"
        token = EncryptorX.encrypt(msg, delimiter='$')

        # Alter an actual hex byte inside a NULL wrapper
        tampered_token = EncryptorX._DEOBFUSCATE_REGEX.sub(
            lambda m: m.group(0).replace(
                next(g for g in m.groups() if g is not None),
                f"{int(next(g for g in m.groups() if g is not None), 16) ^ 0x01:02x}"
            ),
            token,
            count=1
        )

        with self.assertRaises(ValueError):
            EncryptorX.decrypt(tampered_token)

    def test_file_encryption_decryption(self):
        sample_path = os.path.join(PROJECT_DIR, "test_file_temp.bin")
        data = b"Contenido binario secreto: " + os.urandom(1024)
        with open(sample_path, "wb") as f:
            f.write(data)

        try:
            # Sin contraseña
            enc_file = EncryptorX.encrypt_file(sample_path)
            self.assertTrue(enc_file.exists())
            dec_file = EncryptorX.decrypt_file(enc_file, output_path=sample_path + ".out")
            self.assertEqual(dec_file.read_bytes(), data)
            if dec_file.exists():
                os.remove(dec_file)
            if enc_file.exists():
                os.remove(enc_file)

            # Con contraseña
            enc_file_pwd = EncryptorX.encrypt_file(sample_path, password="Pass1234Secure")
            dec_file_pwd = EncryptorX.decrypt_file(enc_file_pwd, password="Pass1234Secure")
            self.assertEqual(dec_file_pwd.read_bytes(), data)
            if dec_file_pwd.exists():
                os.remove(dec_file_pwd)
            if enc_file_pwd.exists():
                os.remove(enc_file_pwd)

        finally:
            if os.path.exists(sample_path):
                os.remove(sample_path)

    def test_cli_execution(self):
        # Test CLI encryption
        msg = "CLI_Test_Message_123"
        proc = subprocess.run(
            [sys.executable, os.path.join(PROJECT_DIR, "EncryptorX.py"), "-e", msg, "-s", "%"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.assertEqual(proc.returncode, 0)
        token = proc.stdout.strip()
        self.assertIn("%", token)

        # Test CLI decryption
        proc_dec = subprocess.run(
            [sys.executable, os.path.join(PROJECT_DIR, "EncryptorX.py"), "-d", token],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.assertEqual(proc_dec.returncode, 0)
        self.assertEqual(proc_dec.stdout.strip(), msg)

    def test_quick_tools(self):
        pwd = EncryptorX.generate_random_password(32)
        self.assertEqual(len(pwd), 32)
        b64 = EncryptorX.base64_encode("Prueba")
        self.assertEqual(EncryptorX.base64_decode(b64), "Prueba")

if __name__ == "__main__":
    unittest.main(verbosity=2)
