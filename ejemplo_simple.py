# -*- coding: utf-8 -*-
"""
=============================================================================
EJEMPLO SIMPLE - BIBLIOTECA ENCRYPTORX
=============================================================================
Este script demuestra en pocos pasos cómo utilizar todas las funciones
principales de nuestra librería 'encryptorx':

1. Cifrado y descifrado directo de texto (Null-Obfuscated Cipher).
2. Cifrado de texto protegido con contraseña (PBKDF2 + HMAC-SHA256).
3. Cifrado y descifrado seguro de archivos (.enc).
4. Esteganografía en imágenes (Pixel Shuffling) con métricas PSNR.
=============================================================================
"""

import os
from pathlib import Path
from PIL import Image

# Importamos las funciones directamente de nuestra librería
import encryptorx


def demo_cifrado_texto():
    print("\n" + "=" * 65)
    print("1. CIFRADO Y DESCIFRADO DE TEXTO")
    print("=" * 65)

    mensaje_original = "Hola, este es un mensaje secreto usando EncryptorX."

    # A) Modo Directo (sin contraseña)
    token = encryptorx.encrypt(mensaje_original)
    texto_recuperado = encryptorx.decrypt(token)

    print(f"[*] Mensaje original:      {mensaje_original}")
    print(f"[*] Token cifrado directo: {token[:45]}... (longitud: {len(token)} chars)")
    print(f"[*] Texto descifrado:      {texto_recuperado}")
    assert mensaje_original == texto_recuperado, "Error en modo directo"
    print("[OK] Modo directo completado con exito.")

    # B) Modo Protegido con Contrasena
    password = "MiClaveSuperSegura2026!"
    token_pwd = encryptorx.encrypt(mensaje_original, password=password)
    texto_pwd = encryptorx.decrypt(token_pwd, password=password)

    print(f"\n[*] Token con contrasena:  {token_pwd[:45]}...")
    print(f"[*] Texto descifrado:      {texto_pwd}")
    assert mensaje_original == texto_pwd, "Error con contrasena"

    # Prueba de protección contra contraseñas incorrectas
    try:
        encryptorx.decrypt(token_pwd, password="ClaveEquivocada")
        print("[!] Alerta: no debería descifrar con contraseña mala.")
    except Exception:
        print("[OK] Protección verificada: rechaza contraseñas incorrectas.")


def demo_cifrado_archivos():
    print("\n" + "=" * 65)
    print("2. CIFRADO Y DESCIFRADO DE ARCHIVOS (.enc)")
    print("=" * 65)

    # 1. Crear un archivo de prueba
    archivo_prueba = Path("mi_documento.txt")
    archivo_prueba.write_text("Datos confidenciales: Contrato firmado el 2026.", encoding="utf-8")
    print(f"[*] Archivo de prueba creado: {archivo_prueba.name}")

    password_archivo = "PasswordArchivos99#"

    # 2. Cifrar el archivo -> genera mi_documento.txt.enc
    archivo_cifrado = encryptorx.encrypt_file(archivo_prueba, password=password_archivo)
    print(f"[*] Archivo cifrado creado:   {archivo_cifrado}")

    # 3. Descifrar el archivo
    archivo_restaurado = encryptorx.decrypt_file(archivo_cifrado, password=password_archivo)
    print(f"[*] Archivo restaurado en:    {archivo_restaurado}")

    contenido_final = Path(archivo_restaurado).read_text(encoding="utf-8")
    print(f"[*] Contenido verificado:     {contenido_final}")

    # Limpieza de archivos de prueba
    for f in [archivo_prueba, Path(archivo_cifrado), Path(archivo_restaurado)]:
        if f.exists():
            f.unlink()
    print("[OK] Cifrado de archivos verificado con exito.")


def demo_esteganografia_imagenes():
    print("\n" + "=" * 65)
    print("3. ESTEGANOGRAFIA EN IMAGENES (PIXEL SHUFFLING)")
    print("=" * 65)

    # 1. Crear una imagen portadora sintetica (PNG)
    img_portadora = Path("portadora_demo.png")
    img_salida = Path("stego_demo.png")

    img = Image.new("RGB", (200, 200), color=(50, 100, 150))
    # Agregar algo de textura
    pix = img.load()
    for x in range(200):
        for y in range(200):
            pix[x, y] = ((x * 4) % 256, (y * 3) % 256, (x + y) % 256)
    img.save(img_portadora, format="PNG")
    print(f"[*] Imagen portadora creada:  {img_portadora} (200x200 pixeles)")

    # 2. Consultar capacidad disponible
    capacidad = encryptorx.get_image_capacity(img_portadora, bits_per_channel=1, channels="RGB")
    print(f"[*] Capacidad neta de datos:  {capacidad['net_capacity_bytes']:,} bytes (~{capacidad['net_capacity_kb']} KB)")
    print(f"[*] Nivel de Sigilo:          {capacidad['stealth_rating']}")

    # 3. Ocultar mensaje secreto
    secreto = "Coordenadas secretas: 40.4168 N, 3.7038 W. Operacion EncryptorX."
    password_stego = "ClaveSecretaEstego2026"

    encryptorx.hide_text(
        carrier_image_path=img_portadora,
        text=secreto,
        output_image_path=img_salida,
        password=password_stego,
        bits_per_channel=1,  # 1 bit por canal = Ultra Sigilo
        channels="RGB"       # Canales a usar
    )
    print(f"[*] Imagen con datos oculta:  {img_salida}")

    # 4. Calcular metricas forenses (PSNR y MSE)
    metricas = encryptorx.calculate_metrics(img_portadora, img_salida)
    print(f"[*] Calidad Visual (PSNR):    {metricas['psnr_db']} dB ({metricas['human_perceptibility']})")
    print(f"[*] Error Cuadratico (MSE):   {metricas['mse']}")
    print(f"[*] Pixeles modificados:      {metricas['changed_channels_count']} ({metricas['changed_channels_pct']}%)")

    # 5. Extraer el mensaje secreto de la imagen
    mensaje_recuperado = encryptorx.extract_text(img_salida, password=password_stego)
    print(f"[*] Mensaje extraido:         '{mensaje_recuperado}'")
    assert secreto == mensaje_recuperado, "Error en extraccion esteganografica"

    # Limpieza
    for f in [img_portadora, img_salida]:
        if f.exists():
            f.unlink()

    print("[OK] Esteganografia con Pixel Shuffling verificada con exito.")


if __name__ == "__main__":
    print("Iniciando demostracion de la libreria EncryptorX...")
    demo_cifrado_texto()
    demo_cifrado_archivos()
    demo_esteganografia_imagenes()
    print("\n" + "=" * 65)
    print("TODAS LAS PRUEBAS DE LA LIBRERIA FINALIZARON CON EXITO!")
    print("=" * 65)

