"""
Comprehensive Unit & Integration Test Suite for EncryptorX Cryptographic Engine Expansion
Tests:
- ChaCha20-Poly1305 (RFC 8439) AEAD
- AES-256 CTR & GCM AEAD
- X25519 ECDH Key Exchange (RFC 7748)
- Ed25519 Digital Signatures (RFC 8032)
- Shamir's Secret Sharing Scheme (k, n) over GF(256)
- Encrypted Multi-File Vault Container (.vault) with MFA & Compression
- FIPS 140-2 / NIST SP 800-22 Entropy & Randomness Quality Auditor
"""

import os
import shutil
import tempfile
import unittest
import encryptorx


class TestChaCha20Poly1305(unittest.TestCase):
    def test_roundtrip(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"Confidential enterprise payload for ChaCha20-Poly1305 validation."
        aad = b"header-metadata-id-4912"
        ciphertext, tag = encryptorx.chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        decrypted = encryptorx.chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
        self.assertEqual(decrypted, plaintext)

    def test_tamper_detection(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"Critical cryptographic payload"
        ciphertext, tag = encryptorx.chacha20_poly1305_encrypt(key, nonce, plaintext)
        
        # Corrupt one byte of ciphertext
        bad_ciphertext = bytearray(ciphertext)
        bad_ciphertext[0] ^= 0x01
        with self.assertRaises(ValueError):
            encryptorx.chacha20_poly1305_decrypt(key, nonce, bytes(bad_ciphertext), tag)

        # Corrupt one byte of tag
        bad_tag = bytearray(tag)
        bad_tag[0] ^= 0x01
        with self.assertRaises(ValueError):
            encryptorx.chacha20_poly1305_decrypt(key, nonce, ciphertext, bytes(bad_tag))

    def test_aad_mismatch(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"Authenticated associated data test"
        ciphertext, tag = encryptorx.chacha20_poly1305_encrypt(key, nonce, plaintext, b"correct_aad")
        with self.assertRaises(ValueError):
            encryptorx.chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, b"tampered_aad")


class TestAES256(unittest.TestCase):
    def test_ctr_mode(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"Pure AES-256 CTR mode encryption test across arbitrary byte boundaries."
        encrypted = encryptorx.aes256_ctr_encrypt(key, nonce, plaintext)
        decrypted = encryptorx.aes256_ctr_decrypt(key, nonce, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_gcm_mode(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"High-security AES-256-GCM AEAD payload with GHASH integrity."
        aad = b"enterprise-packet-v2"
        encrypted, tag = encryptorx.aes256_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = encryptorx.aes256_gcm_decrypt(key, nonce, encrypted, tag, aad)
        self.assertEqual(decrypted, plaintext)

    def test_gcm_tamper(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"Secure banking transaction wire details"
        encrypted, tag = encryptorx.aes256_gcm_encrypt(key, nonce, plaintext)
        bad_encrypted = bytearray(encrypted)
        bad_encrypted[0] ^= 0xFF
        with self.assertRaises(ValueError):
            encryptorx.aes256_gcm_decrypt(key, nonce, bytes(bad_encrypted), tag)


class TestAsymmetric(unittest.TestCase):
    def test_x25519_ecdh(self):
        alice_priv, alice_pub = encryptorx.generate_x25519_keypair()
        bob_priv, bob_pub = encryptorx.generate_x25519_keypair()
        
        alice_shared = encryptorx.derive_shared_secret(alice_priv, bob_pub)
        bob_shared = encryptorx.derive_shared_secret(bob_priv, alice_pub)
        
        self.assertEqual(alice_shared, bob_shared)
        self.assertEqual(len(alice_shared), 32)

    def test_ed25519_signatures(self):
        priv_key, pub_key = encryptorx.generate_signing_keypair()
        message = b"Digital contract agreement signed by Edwards25519 cryptographic key."
        
        signature = encryptorx.ed25519_sign(priv_key, message)
        self.assertEqual(len(signature), 64)
        
        # Verify valid signature
        self.assertTrue(encryptorx.ed25519_verify(pub_key, message, signature))
        
        # Verify tampered message fails
        self.assertFalse(encryptorx.ed25519_verify(pub_key, message + b"tampered", signature))
        
        # Verify tampered signature fails
        bad_sig = bytearray(signature)
        bad_sig[0] ^= 0x55
        self.assertFalse(encryptorx.ed25519_verify(pub_key, message, bytes(bad_sig)))


class TestShamirSecretSharing(unittest.TestCase):
    def test_threshold_reconstruction(self):
        secret = b"ULTRA-SECRET-MASTER-KEY-CORP-9842"
        shares = encryptorx.split_secret(secret, k=3, n=5)
        self.assertEqual(len(shares), 5)
        
        # Any 3 shares reconstruct correctly
        subset_1 = [shares[0], shares[1], shares[2]]
        self.assertEqual(encryptorx.combine_shares(subset_1), secret)
        
        subset_2 = [shares[1], shares[3], shares[4]]
        self.assertEqual(encryptorx.combine_shares(subset_2), secret)
        
        subset_3 = [shares[0], shares[2], shares[4]]
        self.assertEqual(encryptorx.combine_shares(subset_3), secret)

    def test_threshold_too_few_shares(self):
        secret = b"Confidential"
        shares = encryptorx.split_secret(secret, k=3, n=5)
        
        # With only 2 shares, reconstruction does not match
        subset = [shares[0], shares[1]]
        recovered = encryptorx.combine_shares(subset)
        self.assertNotEqual(recovered, secret)

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            encryptorx.split_secret(b"test", k=6, n=5)
        with self.assertRaises(ValueError):
            encryptorx.split_secret(b"test", k=1, n=5)


class TestVaultContainer(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="vault_test_")
        self.source_dir = os.path.join(self.test_dir, "source")
        self.out_dir = os.path.join(self.test_dir, "extracted")
        os.makedirs(self.source_dir, exist_ok=True)
        
        # Create nested test files
        with open(os.path.join(self.source_dir, "file1.txt"), "w") as f:
            f.write("Alpha content for vault testing.")
        
        sub = os.path.join(self.source_dir, "nested", "inner")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, "secret.bin"), "wb") as f:
            f.write(os.urandom(1024))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_vault_roundtrip_password_and_keyfile(self):
        vault_path = os.path.join(self.test_dir, "archive.vault")
        keyfile_path = os.path.join(self.test_dir, "master.key")
        password = "EnterpriseSecurePassphrase!2026"
        
        # Generate keyfile for MFA
        encryptorx.generate_keyfile(keyfile_path)
        
        # Pack and encrypt with ChaCha20
        created = encryptorx.create_vault(
            source_dir=self.source_dir,
            vault_path=vault_path,
            password=password,
            keyfile_path=keyfile_path,
            cipher="chacha20",
        )
        self.assertTrue(os.path.exists(created))
        
        # Inspect vault
        info = encryptorx.inspect_vault(
            vault_path=vault_path,
            password=password,
            keyfile_path=keyfile_path,
        )
        self.assertEqual(info["cipher"], "ChaCha20-Poly1305")
        self.assertEqual(info["file_count"], 2)
        
        # Extract vault
        extracted = encryptorx.extract_vault(
            vault_path=vault_path,
            output_dir=self.out_dir,
            password=password,
            keyfile_path=keyfile_path,
        )
        self.assertEqual(len(extracted), 2)
        
        # Verify content fidelity
        with open(os.path.join(self.source_dir, "file1.txt"), "r") as f_orig:
            with open(os.path.join(self.out_dir, "file1.txt"), "r") as f_ext:
                self.assertEqual(f_orig.read(), f_ext.read())

    def test_vault_aes_gcm_mode(self):
        vault_path = os.path.join(self.test_dir, "aes_archive.vault")
        password = "AESPassword2026!"
        encryptorx.create_vault(
            source_dir=self.source_dir,
            vault_path=vault_path,
            password=password,
            cipher="aes",
        )
        info = encryptorx.inspect_vault(vault_path=vault_path, password=password)
        self.assertEqual(info["cipher"], "AES-256-GCM")
        
        out_aes = os.path.join(self.test_dir, "out_aes")
        extracted = encryptorx.extract_vault(vault_path=vault_path, output_dir=out_aes, password=password)
        self.assertEqual(len(extracted), 2)

    def test_vault_wrong_password_rejected(self):
        vault_path = os.path.join(self.test_dir, "test.vault")
        encryptorx.create_vault(
            source_dir=self.source_dir,
            vault_path=vault_path,
            password="CorrectPassword123!",
        )
        with self.assertRaises(ValueError):
            encryptorx.extract_vault(
                vault_path=vault_path,
                output_dir=self.out_dir,
                password="WrongPassword999!",
            )


class TestEntropyAuditor(unittest.TestCase):
    def test_high_entropy_random_data(self):
        random_sample = os.urandom(3000)
        report = encryptorx.audit_randomness(random_sample)
        
        self.assertGreaterEqual(report["shannon_entropy"], 7.8)
        self.assertTrue(report["tests"]["monobit"]["passed"])
        self.assertTrue(report["tests"]["poker"]["passed"])
        self.assertTrue(report["tests"]["long_run"]["passed"])
        self.assertTrue(report["all_passed"])

    def test_low_entropy_data(self):
        biased_sample = b"\xaa" * 3000  # Constant repeating pattern
        report = encryptorx.audit_randomness(biased_sample)
        self.assertFalse(report["all_passed"])


if __name__ == "__main__":
    unittest.main()
