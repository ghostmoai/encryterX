# -*- coding: utf-8 -*-
"""
Test de Interoperabilidad Total Multi-Lenguaje para EncryptorX v3.0.0
Prueba todas las combinaciones posibles de cifrado y descifrado cruzado entre:
- Python (EncryptorX.py)
- C (native/c/encryptorx_c.exe)
- C++ (native/cpp/encryptorx_cpp.exe)
- Rust (native/rust/encryptorx/target/release/encryptorx_rs.exe)
"""

import os
import sys
import subprocess
import unittest

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import EncryptorX

C_EXE = os.path.join(PROJECT_DIR, "native", "c", "encryptorx_c.exe")
CPP_EXE = os.path.join(PROJECT_DIR, "native", "cpp", "encryptorx_cpp.exe")
RUST_EXE = os.path.join(PROJECT_DIR, "native", "rust", "encryptorx", "target", "release", "encryptorx_rs.exe")

def run_cmd(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    return p.stdout.strip()

class TestCrossLanguageInteroperability(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Verify all native binaries exist
        for path, name in [(C_EXE, "C"), (CPP_EXE, "C++"), (RUST_EXE, "Rust")]:
            if not os.path.exists(path):
                raise RuntimeError(f"El ejecutable de {name} no existe en: {path}")

    def test_python_to_all(self):
        msg = "Mensaje originado en Python para C, C++ y Rust"
        token = EncryptorX.encrypt(msg, delimiter='$')

        # C descifra Python
        c_dec = run_cmd([C_EXE, "-d", token])
        self.assertEqual(c_dec, msg, "C no pudo descifrar el token de Python")

        # C++ descifra Python
        cpp_dec = run_cmd([CPP_EXE, "-d", token])
        self.assertEqual(cpp_dec, msg, "C++ no pudo descifrar el token de Python")

        # Rust descifra Python
        rust_dec = run_cmd([RUST_EXE, "-d", token])
        self.assertEqual(rust_dec, msg, "Rust no pudo descifrar el token de Python")

    def test_c_to_all(self):
        msg = "Mensaje originado en C para Python, C++ y Rust"
        token = run_cmd([C_EXE, "-e", msg, "", "%"])

        # Python descifra C
        py_dec = EncryptorX.decrypt(token)
        self.assertEqual(py_dec, msg, "Python no pudo descifrar el token de C")

        # C++ descifra C
        cpp_dec = run_cmd([CPP_EXE, "-d", token])
        self.assertEqual(cpp_dec, msg, "C++ no pudo descifrar el token de C")

        # Rust descifra C
        rust_dec = run_cmd([RUST_EXE, "-d", token])
        self.assertEqual(rust_dec, msg, "Rust no pudo descifrar el token de C")

    def test_cpp_to_all(self):
        msg = "Mensaje originado en C++ para Python, C y Rust"
        token = run_cmd([CPP_EXE, "-e", msg, "", "&"])

        # Python descifra C++
        py_dec = EncryptorX.decrypt(token)
        self.assertEqual(py_dec, msg, "Python no pudo descifrar el token de C++")

        # C descifra C++
        c_dec = run_cmd([C_EXE, "-d", token])
        self.assertEqual(c_dec, msg, "C no pudo descifrar el token de C++")

        # Rust descifra C++
        rust_dec = run_cmd([RUST_EXE, "-d", token])
        self.assertEqual(rust_dec, msg, "Rust no pudo descifrar el token de C++")

    def test_rust_to_all(self):
        msg = "Mensaje originado en Rust para Python, C y C++"
        token = run_cmd([RUST_EXE, "-e", msg, "", "#"])

        # Python descifra Rust
        py_dec = EncryptorX.decrypt(token)
        self.assertEqual(py_dec, msg, "Python no pudo descifrar el token de Rust")

        # C descifra Rust
        c_dec = run_cmd([C_EXE, "-d", token])
        self.assertEqual(c_dec, msg, "C no pudo descifrar el token de Rust")

        # C++ descifra Rust
        cpp_dec = run_cmd([CPP_EXE, "-d", token])
        self.assertEqual(cpp_dec, msg, "C++ no pudo descifrar el token de Rust")

    def test_password_cross_language(self):
        msg = "Mensaje ultra confidencial con clave PBKDF2 cruzada"
        pwd = "ClaveMaestraCruzada_2026"

        # Python cifra con contraseña
        token_py = EncryptorX.encrypt(msg, password=pwd, delimiter='$')

        # C descifra con contraseña
        c_dec = run_cmd([C_EXE, "-d", token_py, pwd])
        self.assertEqual(c_dec, msg)

        # C++ descifra con contraseña
        cpp_dec = run_cmd([CPP_EXE, "-d", token_py, pwd])
        self.assertEqual(cpp_dec, msg)

        # Rust descifra con contraseña
        rust_dec = run_cmd([RUST_EXE, "-d", token_py, pwd])
        self.assertEqual(rust_dec, msg)

        # Rust cifra con contraseña
        token_rust = run_cmd([RUST_EXE, "-e", msg, pwd, "%"])

        # Python descifra Rust con contraseña
        py_dec = EncryptorX.decrypt(token_rust, password=pwd)
        self.assertEqual(py_dec, msg)

        # C descifra Rust con contraseña
        c_dec2 = run_cmd([C_EXE, "-d", token_rust, pwd])
        self.assertEqual(c_dec2, msg)

if __name__ == "__main__":
    unittest.main(verbosity=2)
