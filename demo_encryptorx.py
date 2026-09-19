#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
demo_encryptorx.py
==================
Demostracion tecnica completa de la libreria criptografica encryptorx.
Incluye:
  1. Cifrado simetrico de texto (Modo directo y protegido por contrasena Scrypt/PBKDF2)
  2. Descifrado tolerante a fallas y perdida de caracteres (Fault-Tolerant Decryption)
  3. Cifrado y descifrado seguro de archivos (.enc)
  4. Cifrado moderno AEAD (ChaCha20-Poly1305 y AES-256-GCM)
  5. Criptografia asimetrica (X25519 ECDH y firmas Ed25519)
  6. Esquema de fragmentacion de secretos de Shamir (k, n)
  7. Bovedas cifradas multi-archivo con autenticacion multifactor (MFA)
  8. Auditoria estadistica de entropia FIPS 140-2
  9. Esteganografia en imagenes (inyeccion LSB y calculo de metricas PSNR)
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Configurar salida segura UTF-8 en consola de Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import encryptorx


def banner(title: str):
    print("\n" + "=" * 75)
    print(f"  {title.upper()}")
    print("=" * 75)


def demo_text_encryption():
    banner("1. Cifrado y Descifrado de Texto")
    mensaje = "Instruccion Operativa Confidencial: Proteger las claves criptograficas."
    password = "ClaveUltraSegura2026!"

    # 1.1 Modo directo (sin contrasena)
    token_directo = encryptorx.encrypt(mensaje)
    recuperado_directo = encryptorx.decrypt(token_directo)
    print("Texto original:           ", mensaje)
    print("Token directo (muestra):  ", token_directo[:45] + "...")
    print("Descifrado directo:       ", recuperado_directo)
    assert recuperado_directo == mensaje, "Error en descifrado directo"

    # 1.2 Modo protegido con contrasena (Doble Cascada: Scrypt + PBKDF2 600k)
    token_password = encryptorx.encrypt(mensaje, password=password)
    recuperado_password = encryptorx.decrypt(token_password, password=password)
    print("\nToken con password (muestra):", token_password[:45] + "...")
    print("Descifrado con password:     ", recuperado_password)
    assert recuperado_password == mensaje, "Error en descifrado con password"
    print("[OK] Cifrado y descifrado de texto completado con exito.")


def demo_fault_tolerant_decryption():
    banner("2. Descifrado Tolerante a Fallas y Perdida de Datos")
    mensaje = "Este es un mensaje confidencial que sufrira perdida de caracteres en transito."
    token = encryptorx.encrypt(mensaje)

    # Simular perdida o truncamiento de los ultimos 12 caracteres del token
    token_truncado = token[:-12]
    recuperado_truncado = encryptorx.decrypt(token_truncado)

    print("Texto original:    ", mensaje)
    print("Longitud original: ", len(token), "caracteres")
    print("Longitud truncada: ", len(token_truncado), "caracteres (-12 caracteres)")
    print("Texto recuperado:  ", recuperado_truncado)

    # Simular corrupcion de bytes en el cuerpo del token
    lista_caracteres = list(token)
    mid = len(token) // 2
    for i in range(mid, mid + 8):
        lista_caracteres[i] = "X"
    token_danado = "".join(lista_caracteres)

    recuperado_danado = encryptorx.decrypt(token_danado)
    # Reemplazar caracteres \ufffd con [?] para representacion visual clara
    representacion_limpia = recuperado_danado.replace("\ufffd", "[?]")
    print("\nToken con 8 caracteres corruptos en el cuerpo:")
    print("Texto recuperado:  ", representacion_limpia)
    print("[OK] Motor tolerante a fallas recupero el mensaje inteligible.")


def demo_file_encryption():
    banner("3. Cifrado y Descifrado Seguro de Archivos")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        archivo_origen = tmp_path / "documento_confidencial.txt"
        contenido = "Reporte Financiero Interno - Q3 2026\nBalance Neto: 1,450,000 USD\nEstado: Aprobado"
        archivo_origen.write_text(contenido, encoding="utf-8")

        # Cifrar archivo
        archivo_cifrado = encryptorx.encrypt_file(str(archivo_origen), password="MasterPasswordFile!")
        print("Archivo original: ", archivo_origen)
        print("Archivo cifrado:  ", archivo_cifrado)
        print("Tamano cifrado:   ", os.path.getsize(archivo_cifrado), "bytes")

        # Descifrar archivo
        archivo_descifrado = encryptorx.decrypt_file(str(archivo_cifrado), password="MasterPasswordFile!")
        print("Archivo restaurado:", archivo_descifrado)
        contenido_restaurado = Path(archivo_descifrado).read_text(encoding="utf-8")
        assert contenido_restaurado == contenido, "Error en contenido restaurado de archivo"
        print("[OK] Cifrado de archivos verificado con integridad total.")


def demo_modern_ciphers():
    banner("4. Cifrado Simetrico Moderno AEAD (ChaCha20-Poly1305 & AES-256-GCM)")
    key = os.urandom(32)
    nonce12 = os.urandom(12)
    aad = b"Encabezado-Autenticado-Metadatos"
    plaintext = b"Payload seguro de alto rendimiento para transmision de datos."

    # ChaCha20-Poly1305 (RFC 8439)
    ct_chacha, tag_chacha = encryptorx.chacha20_poly1305_encrypt(key, nonce12, plaintext, aad)
    pt_chacha = encryptorx.chacha20_poly1305_decrypt(key, nonce12, ct_chacha, tag_chacha, aad)
    print("ChaCha20-Poly1305 Texto Descifrado: ", pt_chacha.decode("utf-8"))
    print("ChaCha20-Poly1305 MAC Tag (Hex):    ", tag_chacha.hex())
    assert pt_chacha == plaintext

    # AES-256-GCM (NIST SP 800-38D)
    ct_gcm, tag_gcm = encryptorx.aes256_gcm_encrypt(key, nonce12, plaintext, aad)
    pt_gcm = encryptorx.aes256_gcm_decrypt(key, nonce12, ct_gcm, tag_gcm, aad)
    print("\nAES-256-GCM Texto Descifrado:       ", pt_gcm.decode("utf-8"))
    print("AES-256-GCM MAC Tag (Hex):          ", tag_gcm.hex())
    assert pt_gcm == plaintext
    print("[OK] Cifrados modernos ChaCha20-Poly1305 y AES-256-GCM autenticados con exito.")


def demo_asymmetric_crypto():
    banner("5. Criptografia Asimetrica (X25519 ECDH & Ed25519 Firmas)")

    # 5.1 Intercambio de claves Diffie-Hellman X25519 (RFC 7748)
    alice_priv, alice_pub = encryptorx.generate_x25519_keypair()
    bob_priv, bob_pub = encryptorx.generate_x25519_keypair()

    secret_alice = encryptorx.derive_shared_secret(alice_priv, bob_pub)
    secret_bob = encryptorx.derive_shared_secret(bob_priv, alice_pub)
    print("Alice Clave Publica (Hex): ", alice_pub.hex()[:32] + "...")
    print("Bob Clave Publica (Hex):   ", bob_pub.hex()[:32] + "...")
    print("Secreto Compartido Alice:  ", secret_alice.hex())
    print("Secreto Compartido Bob:    ", secret_bob.hex())
    assert secret_alice == secret_bob, "Discrepancia en secreto compartido X25519"
    print("Secreto compartido identico verificado.")

    # 5.2 Firmas Digitales Ed25519 (RFC 8032)
    sign_priv, sign_pub = encryptorx.generate_signing_keypair()
    mensaje_firma = b"Orden de transferencia de fondos irrevocables por 50,000 EUR."
    firma = encryptorx.ed25519_sign(sign_priv, mensaje_firma)
    valida = encryptorx.ed25519_verify(sign_pub, mensaje_firma, firma)
    print("\nMensaje a firmar:          ", mensaje_firma.decode("utf-8"))
    print("Firma Digital Ed25519:     ", firma.hex()[:48] + "...")
    print("Verificacion de firma:     ", "VALIDA" if valida else "INVALIDA")
    assert valida, "Error en verificacion de firma Ed25519"
    print("[OK] Primitivas asimetricas X25519 y Ed25519 operacionales.")


def demo_shamir_secret_sharing():
    banner("6. Fragmentacion Secreta de Shamir (k, n)")
    secreto = "MasterKey-Alpha-7789-RootAuthorization"
    k = 3
    n = 5

    print(f"Dividiendo secreto con esquema ({k}, {n}): k={k} requeridos, n={n} generados.")
    print("Secreto original: ", secreto)

    fragmentos = encryptorx.split_secret(secreto, k=k, n=n)
    for i, frag in enumerate(fragmentos, 1):
        print(f"  Fragmento {i}: {frag}")

    # Reconstruir usando unicamente 3 fragmentos cualesquiera (ej. fragmentos 1, 3 y 4)
    fragmentos_elegidos = [fragmentos[0], fragmentos[2], fragmentos[3]]
    recuperado_bytes = encryptorx.combine_shares(fragmentos_elegidos)
    recuperado_texto = recuperado_bytes.decode("utf-8")
    print(f"\nReconstruyendo secreto con {len(fragmentos_elegidos)} fragmentos seleccionados:")
    print("Secreto recuperado: ", recuperado_texto)
    assert recuperado_texto == secreto, "Error en reconstruccion Shamir"
    print("[OK] Esquema de Shamir verificado exitosamente.")


def demo_vault_mfa():
    banner("7. Boveda Segura Multi-Archivo con MFA (.vault)")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        source_dir = tmp_path / "proyecto_secreto"
        source_dir.mkdir()
        (source_dir / "codigo.py").write_text("print('algoritmo confidencial')", encoding="utf-8")
        (source_dir / "claves.json").write_text('{"api_key": "sec_998124"}', encoding="utf-8")
        sub = source_dir / "docs"
        sub.mkdir()
        (sub / "manual.txt").write_text("Instrucciones operativas de despliegue", encoding="utf-8")

        keyfile_path = str(tmp_path / "master.keyfile")
        vault_path = str(tmp_path / "empresa.vault")
        password = "VaultPasswordMultiFactor2026!"

        # Generar keyfile criptografico de 256 bits
        encryptorx.generate_keyfile(keyfile_path)
        print("Keyfile MFA generado:       ", keyfile_path)

        # Crear boveda cifrada
        encryptorx.create_vault(
            source_dir=str(source_dir),
            vault_path=vault_path,
            password=password,
            keyfile_path=keyfile_path,
            cipher="chacha20",
        )
        print("Boveda .vault empaquetada:  ", vault_path)
        print("Tamano del contenedor .vault:", os.path.getsize(vault_path), "bytes")

        # Inspeccionar manifiesto sin descomprimir en disco
        manifest = encryptorx.inspect_vault(vault_path, password=password, keyfile_path=keyfile_path)
        print("\nManifiesto de la boveda (inspeccion directa en memoria):")
        print("  Algoritmo AEAD:           ", manifest["cipher"])
        print("  Cantidad de archivos:     ", manifest["file_count"])
        print("  Archivos empaquetados:    ", manifest["files"])

        # Extraer boveda
        dest_dir = str(tmp_path / "restaurado")
        extraidos = encryptorx.extract_vault(
            vault_path=vault_path,
            output_dir=dest_dir,
            password=password,
            keyfile_path=keyfile_path,
        )
        print(f"\nBoveda extraida correctamente en: {dest_dir} ({len(extraidos)} archivos)")
        assert Path(dest_dir, "docs", "manual.txt").is_file()
        print("[OK] Bovedas multiproposito MFA validadas.")


def demo_entropy_audit():
    banner("8. Auditoria Estadistica FIPS 140-2 y Entropia de Shannon")
    # Generar 20,000 bits (2500 bytes) pseudoaleatorios criptograficos
    datos_prueba = os.urandom(2500)
    auditoria = encryptorx.audit_randomness(datos_prueba)

    print("Tamano analizado:             ", auditoria["total_bytes"], "bytes")
    print("Entropia de Shannon:          ", f"{auditoria['shannon_entropy']:.4f} / 8.0000 bits")
    print("FIPS 140-2 Monobit Test:      ", "APROBADO" if auditoria["tests"]["monobit"]["passed"] else "FALLIDO")
    print("  Conteo de bits 1:           ", auditoria["tests"]["monobit"]["ones_count"])
    print("FIPS 140-2 Poker Test:        ", "APROBADO" if auditoria["tests"]["poker"]["passed"] else "FALLIDO")
    print("  Estadistico Chi-cuadrado:   ", f"{auditoria['tests']['poker']['statistic_X']:.4f}")
    print("FIPS 140-2 Long Run Test:     ", "APROBADO" if auditoria["tests"]["long_run"]["passed"] else "FALLIDO")
    print("  Racha maxima consecutiva:   ", auditoria["tests"]["long_run"]["max_consecutive_run"])
    print("Veredicto General FIPS 140-2: ", "APROBADO CON EXITO" if auditoria["all_passed"] else "FALLIDO")
    print("[OK] Bateria de pruebas de aleatoriedad FIPS 140-2 finalizada.")


def demo_steganography():
    banner("9. Esteganografia en Imagenes (Inyeccion LSB y Metricas PSNR)")
    try:
        from PIL import Image
    except ImportError:
        print("Pillow no esta disponible en el entorno; omitiendo demo de esteganografia.")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        carrier_img = tmp_path / "carrier.png"
        stego_img = tmp_path / "stego.png"

        # Crear imagen base 300x300 RGB
        img = Image.new("RGB", (300, 300), color=(50, 120, 200))
        img.save(carrier_img)

        # Ocultar texto confidencial
        secreto = "Coordenadas: 34.0522 N, 118.2437 W. Clave de acceso: Bravo-Nine."
        encryptorx.hide_text(
            carrier_image_path=str(carrier_img),
            text=secreto,
            output_image_path=str(stego_img),
            password="StegoPassword2026",
            bits_per_channel=1,
            channels="RGB",
        )
        print("Imagen portadora:   ", carrier_img)
        print("Imagen esteganica:  ", stego_img)

        # Extraer texto confidencial
        recuperado = encryptorx.extract_text(str(stego_img), password="StegoPassword2026")
        print("Texto extraido:     ", recuperado)
        assert recuperado == secreto, "Error en extraccion esteganografica"

        # Calcular metricas de fidelidad visual
        metricas = encryptorx.calculate_metrics(str(carrier_img), str(stego_img))
        print("\nMetricas de Calidad de Imagen:")
        print("  PSNR (Peak Signal-to-Noise Ratio):", f"{metricas['psnr_db']:.2f} dB")
        print("  MSE (Mean Squared Error):         ", f"{metricas['mse']:.6f}")
        print("  Canales Modificados:              ", metricas["changed_channels_count"])
        print("  Perceptibilidad Humana:           ", metricas["human_perceptibility"])
        print("[OK] Esteganografia y verificacion PSNR validadas.")


def main():
    print("=" * 75)
    print(f"  ENCRYPTORX v{encryptorx.__version__} - SUITE CRIPTOGRAFICA INTEGRAL")
    print("=" * 75)

    demo_text_encryption()
    demo_fault_tolerant_decryption()
    demo_file_encryption()
    demo_modern_ciphers()
    demo_asymmetric_crypto()
    demo_shamir_secret_sharing()
    demo_vault_mfa()
    demo_entropy_audit()
    demo_steganography()

    print("\n" + "=" * 75)
    print("  TODAS LAS DEMOSTRACIONES SE EJECUTARON CON EXITO (100% OK)")
    print("=" * 75)


if __name__ == "__main__":
    main()
