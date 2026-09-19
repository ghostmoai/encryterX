"""
Suite de Pruebas Automatizadas de Esteganografía con Pixel Shuffling.
Verifica la integridad de inyección, extracción, blindaje criptográfico,
preservación de calidad visual (PSNR) y resistencia a inspección secuencial.
"""
import os
import tempfile
import unittest
import hashlib
from pathlib import Path
from PIL import Image

import encryptorx.stego as stego
from encryptorx.stego import (
    hide_text,
    extract_text,
    hide_file,
    extract_file,
    get_image_capacity,
    calculate_metrics,
    AuthenticationError,
    CapacityError,
    CorruptDataError,
)


class TestPixelShufflingSteganography(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

        # Crear una imagen sintética RGB de 200x200 píxeles
        self.carrier_rgb = self.dir_path / "carrier_rgb.png"
        img_rgb = Image.new("RGB", (200, 200), color=(70, 130, 180))
        # Agregar algo de variación de color realista
        pixels = img_rgb.load()
        for x in range(200):
            for y in range(200):
                pixels[x, y] = ((x * 3) % 256, (y * 5) % 256, (x + y) % 256)
        img_rgb.save(self.carrier_rgb, format="PNG")

        # Crear una imagen sintética RGBA de 150x150 píxeles con canal Alfa
        self.carrier_rgba = self.dir_path / "carrier_rgba.png"
        img_rgba = Image.new("RGBA", (150, 150), color=(100, 150, 200, 220))
        img_rgba.save(self.carrier_rgba, format="PNG")

        # Crear una imagen BMP de 120x120
        self.carrier_bmp = self.dir_path / "carrier_bmp.bmp"
        img_bmp = Image.new("RGB", (120, 120), color=(210, 105, 30))
        img_bmp.save(self.carrier_bmp, format="BMP")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_direct_mode_text_roundtrip(self):
        """Prueba de ocultación y extracción directa de texto sin contraseña."""
        secret_msg = "¡Hola mundo! Este es un mensaje secreto inyectado con Pixel Shuffling 🚀."
        out_img = self.dir_path / "stego_text_direct.png"

        hide_text(self.carrier_rgb, secret_msg, out_img, password=None)
        self.assertTrue(out_img.exists())

        recovered = extract_text(out_img, password=None)
        self.assertEqual(secret_msg, recovered)

    def test_password_protected_text_roundtrip(self):
        """Prueba de ocultación de texto con clave PBKDF2 y HMAC anti-tamper."""
        secret_msg = "Datos bancarios de alta confidencialidad: IBAN ES91 2100 0418 4502 0005 1332"
        password = "SuperPasswordSegura2026!#"
        out_img = self.dir_path / "stego_text_pwd.png"

        hide_text(self.carrier_rgb, secret_msg, out_img, password=password)

        # 1. Extracción con la clave correcta
        recovered = extract_text(out_img, password=password)
        self.assertEqual(secret_msg, recovered)

        # 2. Extracción con clave incorrecta debe ser rechazada de inmediato
        with self.assertRaises((AuthenticationError, CorruptDataError)):
            extract_text(out_img, password="PasswordEquivocada")

        # 3. Extracción sin clave debe ser rechazada
        with self.assertRaises((AuthenticationError, CorruptDataError)):
            extract_text(out_img, password=None)

    def test_binary_file_embedding_and_extraction(self):
        """Prueba de ocultación de archivo binario arbitrario (exactitud byte a byte)."""
        # Crear un archivo binario aleatorio con metadatos
        sample_file = self.dir_path / "documento_clasificado.pdf"
        # 4 KB de datos binarios arbitrarios
        raw_content = os.urandom(4096)
        sample_file.write_bytes(raw_content)
        original_hash = hashlib.sha256(raw_content).hexdigest()

        out_img = self.dir_path / "stego_file.png"
        pwd = "FileStegoKey99!"

        hide_file(self.carrier_rgb, sample_file, out_img, password=pwd)
        self.assertTrue(out_img.exists())

        # Extraer archivo
        extract_folder = self.dir_path / "recovered_files"
        saved_file, filename = extract_file(out_img, output_dir=extract_folder, password=pwd)

        self.assertEqual("documento_clasificado.pdf", filename)
        self.assertTrue(saved_file.exists())

        recovered_bytes = saved_file.read_bytes()
        recovered_hash = hashlib.sha256(recovered_bytes).hexdigest()

        self.assertEqual(original_hash, recovered_hash)
        self.assertEqual(len(raw_content), len(recovered_bytes))

    def test_bmp_format_roundtrip(self):
        """Prueba de soporte completo para imágenes BMP sin pérdida."""
        secret = "Prueba en mapa de bits BMP"
        out_bmp = self.dir_path / "stego_out.bmp"

        hide_text(self.carrier_bmp, secret, out_bmp, password="BmpPassword")
        self.assertTrue(out_bmp.exists())

        rec = extract_text(out_bmp, password="BmpPassword")
        self.assertEqual(secret, rec)

    def test_rgba_alpha_channel_preservation(self):
        """Verifica que en imágenes RGBA el canal de transparencia no sufra ninguna alteración."""
        out_rgba = self.dir_path / "stego_rgba.png"
        hide_text(self.carrier_rgba, "Canal Alfa intacto", out_rgba)

        with Image.open(self.carrier_rgba) as orig, Image.open(out_rgba) as modified:
            orig_alpha = orig.getchannel("A").tobytes()
            mod_alpha = modified.getchannel("A").tobytes()
            self.assertEqual(orig_alpha, mod_alpha, "El canal Alfa no debe ser modificado jamás.")

    def test_pixel_shuffling_scrambles_sequential_inspection(self):
        """
        Demuestra la eficacia del Pixel Shuffling:
        Al leer los primeros bytes secuenciales sin aplicar la permutación,
        no aparece la cabecera 'SX01', demostrando que los datos están dispersos.
        """
        out_img = self.dir_path / "stego_scramble.png"
        hide_text(self.carrier_rgb, "Mensaje para probar dispersión", out_img, password="KeyTest123")

        with Image.open(out_img) as img:
            raw_bytes = img.tobytes()
            # Leer los primeros 32 bits secuenciales
            sequential_bits = []
            for i in range(32):
                sequential_bits.append(raw_bytes[i] & 1)

            first_4_bytes = bytearray()
            for i in range(0, 32, 8):
                byte_val = 0
                for b in sequential_bits[i:i+8]:
                    byte_val = (byte_val << 1) | b
                first_4_bytes.append(byte_val)

            # La cabecera MAGIC no debe estar al principio de forma secuencial
            self.assertNotEqual(stego.MAGIC_HEADER, bytes(first_4_bytes),
                                "El Pixel Shuffling debe romper la lectura secuencial tradicional.")

    def test_visual_metrics_and_psnr(self):
        """Certifica que el PSNR sea > 60 dB y que la alteración máxima por canal sea <= 1."""
        out_img = self.dir_path / "stego_metrics.png"
        hide_text(self.carrier_rgb, "Verificando Peak Signal to Noise Ratio", out_img)

        metrics = calculate_metrics(self.carrier_rgb, out_img)
        self.assertGreater(metrics["psnr_db"], 60.0, f"PSNR debe ser superior a 60 dB (obtenido: {metrics['psnr_db']} dB)")
        self.assertLessEqual(metrics["max_pixel_difference"], 1, "La alteración máxima debe ser 1 (LSB).")
        self.assertEqual("Completely Invisible (PSNR > 65 dB)", metrics["human_perceptibility"])

    def test_bits_per_channel_2_and_4(self):
        """Tests configurable bits_per_channel (2-bit and 4-bit modes)."""
        msg = "Message hidden with 2-bit LSB per channel!"
        out_2bit = self.dir_path / "stego_2bit.png"
        hide_text(self.carrier_rgb, msg, out_2bit, password="Key2Bit", bits_per_channel=2)
        recovered_2bit = extract_text(out_2bit, password="Key2Bit")
        self.assertEqual(msg, recovered_2bit)

        # 4-bit mode
        msg_4 = "High capacity 4-bit LSB mode test!"
        out_4bit = self.dir_path / "stego_4bit.png"
        hide_text(self.carrier_rgb, msg_4, out_4bit, password="Key4Bit", bits_per_channel=4)
        recovered_4bit = extract_text(out_4bit, password="Key4Bit")
        self.assertEqual(msg_4, recovered_4bit)

    def test_channel_selection_blue_only(self):
        """Tests hiding data strictly in the Blue channel for higher human eye insensitivity."""
        msg = "Hidden exclusively in Blue channel pixels!"
        out_b = self.dir_path / "stego_blue.png"
        hide_text(self.carrier_rgb, msg, out_b, password="BlueKey", channels="B")
        rec_b = extract_text(out_b, password="BlueKey")
        self.assertEqual(msg, rec_b)

    def test_stego_engine_class_interface(self):
        """Tests the object-oriented StegoEngine class."""
        engine = stego.StegoEngine(bits_per_channel=2, channels="RGB")
        out = self.dir_path / "engine_test.png"
        engine.hide_text(self.carrier_rgb, "Engine OOP test", out, password="EnginePassword")
        rec = engine.extract_text(out, password="EnginePassword")
        self.assertEqual("Engine OOP test", rec)

    def test_capacity_overflow_protection(self):
        """Verifica que intentar ocultar un payload mayor a la capacidad levante CapacityError."""
        cap = get_image_capacity(self.carrier_bmp)
        max_bytes = cap["net_capacity_bytes"]

        # Intentar ocultar más bytes de los posibles
        huge_data = os.urandom(max_bytes + 2000)
        huge_file = self.dir_path / "huge.bin"
        huge_file.write_bytes(huge_data)

        out_img = self.dir_path / "overflow.png"
        with self.assertRaises(CapacityError):
            hide_file(self.carrier_bmp, huge_file, out_img)


if __name__ == "__main__":
    unittest.main(verbosity=2)
