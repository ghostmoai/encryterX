# EncryptorX Stego: Esteganografía Criptográfica en Imágenes con Pixel Shuffling
**Especificación Técnica, Fundamentos Matemáticos y Manual de la Biblioteca de Python**

---

## 1. Introducción: Criptografía vs. Esteganografía

En la seguridad informática clásica, la **criptografía** y la **esteganografía** cumplen objetivos complementarios pero radicalmente distintos:

- **Criptografía**: Transforma un mensaje inteligible en un criptograma aparentemente aleatorio mediante una clave secreta. Sin embargo, un observador o un analizador de red (DPI - *Deep Packet Inspection*) sabe inequívocamente que se está transmitiendo un secreto, lo que convierte al emisor y receptor en objetivos de interceptación, coacción o bloqueo.
- **Esteganografía**: Oculta la **propia existencia de la comunicación**. El mensaje secreto se incrusta dentro de un archivo portador de apariencia inofensiva (como una fotografía digital PNG o BMP). Para cualquier censor, cortafuegos o tercero, el archivo viaja como una imagen ordinaria que puede abrirse y visualizarse sin levantar la menor sospecha.

**EncryptorX Stego** fusiona lo mejor de ambos mundos: implementa una arquitectura **Encrypt-then-Embed**, donde los datos se cifran primero con primitivas criptográficas robustas (PBKDF2 de 100.000 rondas, cifrado de flujo de 256 bits y autenticación HMAC-SHA256) antes de ser camuflados dentro de los píxeles de la imagen mediante **Pixel Shuffling**.

```
+------------------+     +------------------------+     +--------------------------+
|  Archivo / Texto | --> | Cifrado PBKDF2 + HMAC  | --> | Payload Cifrado          |
|  Secreto         |     | Stream Cipher 256-bit  |     | (Ruido Blanco Puro)      |
+------------------+     +------------------------+     +--------------------------+
                                                                     |
                                                                     v
+------------------+     +------------------------+     +--------------------------+
| Imagen Portadora | --> | Pixel Shuffling LCG    | <-- | Inyección Dispersa       |
| (PNG / BMP)      |     | Permutación Espacial   |     | LSB (1 bit por canal)    |
+------------------+     +------------------------+     +--------------------------+
                                                                     |
                                                                     v
                                                        +--------------------------+
                                                        | Imagen Esteganográfica   |
                                                        | Visualmente Idéntica     |
                                                        | (PSNR > 67 dB)           |
                                                        +--------------------------+
```

---

## 2. La Vulnerabilidad del LSB Tradicional y Por Qué Falla

El método clásico de esteganografía digital es la sustitución del bit menos significativo (**LSB** - *Least Significant Bit*). En una imagen RGB de 24 bits, cada píxel tiene 3 canales de color (Rojo, Verde, Azul), cada uno representado por un byte (0 a 255):

$$\text{Píxel} = [R_7 R_6 R_5 R_4 R_3 R_2 R_1 \mathbf{R_0}, \quad G_7 G_6 G_5 G_4 G_3 G_2 G_1 \mathbf{G_0}, \quad B_7 B_6 B_5 B_4 B_3 B_2 B_1 \mathbf{B_0}]$$

El bit $\mathbf{0}$ tiene un peso de solo $2^0 = 1$. Alterar este bit cambia el brillo del canal en un valor imperceptible de $\Delta = \pm 1$.

### ¿Por qué falla el LSB Secuencial?
En la mayoría de herramientas primitivas, los bits del mensaje se inyectan de forma secuencial: píxel $(0,0)$, píxel $(0,1)$, píxel $(0,2)$, etc. Esta concentración local crea patrones anómalos fatales frente al criptoanálisis:

1. **Inspección de Planos de Bits (Bit-Plane Slicing)**: Herramientas forenses como *StegSolve* aíslan el plano LSB. En una imagen LSB secuencial, se observa una textura densa y estructurada en la esquina superior izquierda que termina bruscamente donde finaliza el mensaje, delatando la manipulación al instante.
2. **Ataque Estadístico Chi-Cuadrado ($\chi^2$)**: La sustitución LSB transforma parejas de valores adyacentes $(2k, 2k+1)$ en una distribución uniforme de probabilidad. Al aplicar la prueba de Chi-Cuadrado de forma secuencial sobre los píxeles, la probabilidad de incrustación salta inmediatamente a $p \approx 1.0$ en la zona inicial y cae a $0$ en la zona no modificada.
3. **Sample Pair Analysis (SPA)**: Detecta cambios en las diferencias entre píxeles vecinos correlacionados espacialmente.

---

## 3. La Solución: Pixel Shuffling Criptográfico (Cycle-Walking LCG)

Para neutralizar por completo estos ataques, **EncryptorX Stego** implementa **Pixel Shuffling**. En lugar de alterar píxeles contiguos, los bits del mensaje se esparcen de manera uniforme y pseudoaleatoria por toda la superficie de la imagen.

### Modelo Matemático de la Permutación
Sea $N = W \times H \times 3$ el número total de ranuras de bits útiles en la imagen. Buscamos una función biyectiva (permutación):

$$\pi: \{0, 1, \dots, N-1\} \longrightarrow \{0, 1, \dots, N-1\}$$

que asigne a cada bit $i$ una coordenada de píxel y canal única sin colisiones y sin consumir memoria proporcional a $N$.

### Generador Congruencial Lineal de Ciclo Completo (Hull-Dobell)
Utilizamos un generador congruencial lineal con módulo $M = 2^k$ (donde $2^k \ge N$ es la menor potencia de dos que cubre $N$):

$$X_{n+1} = (a \cdot X_n + c) \pmod M$$

Por el **Teorema de Hull-Dobell**, el generador tiene período completo $M$ (visita todos y cada uno de los números enteros en $[0, M-1]$ exactamente una vez antes de repetir) si y solo si:
1. $c$ y $M$ son coprimos (como $M = 2^k$, basta con que $c$ sea impar).
2. $a - 1$ es divisible por todos los factores primos de $M$ (es decir, $a - 1$ es par).
3. $a - 1$ es divisible por $4$ si $M$ es divisible por $4$ (garantizado eligiendo $a \equiv 5 \pmod 8$).

### Técnica de Cycle-Walking
Cuando el valor generado $X_{n+1} \ge N$, simplemente se itera la ecuación hasta que $X_{n+m} < N$. Dado que cada valor en $[0, M-1]$ aparece exactamente una vez, la secuencia resultante visita todos y cada uno de los índices de la imagen $[0, N-1]$ con:
- **Consumo de Memoria $O(1)$**: No se almacena una tabla de millones de píxeles en RAM.
- **Cero Colisiones**: Imposible sobrescribir o perder bits.
- **Determinismo Criptográfico**: La semilla inicial y los coeficientes $(a, c, X_0)$ se derivan mediante `PBKDF2-HMAC-SHA256` a partir de la contraseña o la clave maestra.

### Efecto Anti-Forense
Para cualquier analista que examine la imagen con StegSolve o Chi-Cuadrado:
- No existe ningún bloque rectangular ni borde visible.
- Los bits modificados aparecen como ruido térmico natural del sensor fotográfico distribuido de forma homogénea en toda el área de la imagen.
- Incluso el encabezado de metadatos está fragmentado y disperso entre píxeles alejados por miles de posiciones. Sin la contraseña correcta, es matemáticamente imposible localizar el inicio del paquete.

---

## 4. Estructura del Paquete Binario Esteganográfico (Protocolo v2.0)

Antes de inyectarse en los píxeles, los datos se empaquetan en una estructura binaria hermética protegida con autenticación estricta:

| Campo | Longitud | Configuración de Inyección | Descripción |
| :--- | :---: | :---: | :--- |
| **`MAGIC`** | 4 bytes | Fijo: 1 bpc, RGB | Identificador de formato (`b"SX02"` / `0x53 0x58 0x30 0x32`). |
| **`FLAGS`** | 1 byte | Fijo: 1 bpc, RGB | Banderas (`0x01`: Archivo, `0x02`: Con Contraseña, `0x04`: Comprimido). |
| **`CONFIG`** | 1 byte | Fijo: 1 bpc, RGB | Bit 7: Algoritmo (0=LCG, 1=PRNG), Bits 4-6: Canales, Bits 0-3: Bits/canal. |
| **`SALT`** | 16 bytes | Configurable (bpc/chan) | Sal criptográfica aleatoria de 128 bits generada con `os.urandom(16)`. |
| **`FILENAME_LEN`** | 1 byte | Configurable (bpc/chan) | *(Opcional, solo si es archivo)* Longitud $L_f$ del nombre original. |
| **`FILENAME`** | $L_f$ bytes | Configurable (bpc/chan) | *(Opcional)* Nombre UTF-8 del archivo (ej. `"documento.pdf"`). |
| **`PAYLOAD_LEN`** | 4 bytes | Configurable (bpc/chan) | Entero uint32 big-endian con el tamaño en bytes del payload cifrado. |
| **`NONCE`** | 16 bytes | Configurable (bpc/chan) | Vector de inicialización aleatorio de 128 bits para el stream cipher. |
| **`CIPHERTEXT`** | $N$ bytes | Configurable (bpc/chan) | Datos secretos comprimidos y cifrados con `Data ^ Keystream(key, nonce)`. |
| **`HMAC_TAG`** | 16 bytes | Configurable (bpc/chan) | Etiqueta de integridad Encrypt-then-MAC (`HMAC-SHA256(auth_key, header + ciphertext)`). |

### Preamble Bootstrapping Determinista
Los primeros 6 bytes (`MAGIC` + `FLAGS` + `CONFIG` = 48 bits) se inyectan **siempre a 1 bit por canal en modo RGB** dispersos con el generador LCG base. Esto permite que el lector o extractor inspeccione de inmediato cualquier imagen sin necesidad de conocer de antemano el número de bits por canal ni los canales modificados. Las ranuras utilizadas por el preámbulo quedan reservadas y son omitidas por el payload, garantizando cero colisiones.

### Integridad Anti-Tampering
Si un tercero recorta la imagen, cambia colores o introduce una contraseña errónea:
1. El Pixel Shuffler extraerá bits de coordenadas equivocadas.
2. La etiqueta HMAC calculada discrepará de la esperada.
3. El motor rechazará la operación mediante una excepción `AuthenticationError` en tiempo constante, impidiendo la emisión de datos corruptos o ataques de oráculo.

---

## 5. Métricas Matemáticas de Fidelidad Visual

Para certificar que la imagen con datos esteganográficos es indistinguible de la original, se emplean dos métricas científicas:

### 1. Error Cuadrático Medio (MSE - Mean Squared Error)
Mide la variación promedio de los valores de color por canal entre la imagen original $I_1$ y la imagen esteganográfica $I_2$:

$$MSE = \frac{1}{W \cdot H \cdot C} \sum_{x=0}^{W-1} \sum_{y=0}^{H-1} \sum_{c=0}^{C-1} [I_1(x, y, c) - I_2(x, y, c)]^2$$

Como la esteganografía LSB solo cambia el bit menos significativo, la diferencia máxima en cualquier canal es $|I_1 - I_2| \le 1$. Por ende:

$$[I_1 - I_2]^2 \le 1 \implies MSE \le \text{porcentaje de canales modificados} \approx 0.01 \text{ a } 0.1$$

### 2. Relación Señal a Ruido Pico (PSNR - Peak Signal-to-Noise Ratio)
Expresada en decibelios (dB), mide la fidelidad visual:

$$PSNR = 10 \cdot \log_{10} \left( \frac{MAX_I^2}{MSE} \right) = 10 \cdot \log_{10} \left( \frac{255^2}{MSE} \right)$$

- **Escala de Percepción Humana**:
  - $PSNR < 30 \text{ dB}$: Pobre (ruido y artefactos visibles).
  - $PSNR \approx 30 - 40 \text{ dB}$: Aceptable.
  - $PSNR \approx 40 - 50 \text{ dB}$: Muy buena (diferencias prácticamente imperceptibles).
  - $PSNR > 60 \text{ dB}$: **Excelente / Indistinguible para el ojo humano**.
- **Resultados de EncryptorX Stego**: Típicamente **$65 \text{ dB} \text{ a } 75 \text{ dB}$**, garantizando invisibilidad total frente a inspección óptica.

---

## 6. Manual de Uso de la Biblioteca Python (`encryptorx.stego`)

### Instalación e Importación
La biblioteca requiere Python 3.8+ y Pillow (`PIL`). Si `numpy` está presente en el entorno, se aprovecha para cálculos acelerados de métricas.

```python
import encryptorx
# O importación directa de funciones:
from encryptorx import (
    hide_text,
    extract_text,
    hide_file,
    extract_file,
    get_image_capacity,
    calculate_metrics
)
```

---

### Ejemplo 1: Ocultar y Extraer Texto Protegido con Contraseña

```python
from encryptorx import hide_text, extract_text, calculate_metrics

imagen_original = "vacaciones.png"
imagen_secreta = "vacaciones_stego.png"
mensaje = "Coordenadas del refugio seguro: 40.4168° N, 3.7038° W. Clave de acceso: 8841."
password = "MiClaveSuperSegura2026!#"

# 1. Ocultar el texto dentro de la imagen
out_path = hide_text(
    carrier_image_path=imagen_original,
    text=mensaje,
    output_image_path=imagen_secreta,
    password=password,
    compress=True  # Compresión automática zlib
)
print(f"Imagen esteganográfica generada en: {out_path}")

# 2. Calcular la fidelidad visual (PSNR)
metricas = calculate_metrics(imagen_original, imagen_secreta)
print(f"Calidad visual PSNR: {metricas['psnr_db']} dB ({metricas['human_perceptibility']})")

# 3. Extraer el texto secreto
texto_recuperado = extract_text(imagen_secreta, password=password)
print(f"Mensaje recuperado con éxito:\n{texto_recuperado}")
```

---

### Ejemplo 2: Ocultar y Extraer Archivos Binarios Arbitrarios (PDF, ZIP, DOCX)

La función `hide_file` almacena tanto el contenido del archivo como su nombre original.

```python
from encryptorx import hide_file, extract_file

imagen_portadora = "wallpaper_4k.png"
archivo_confidencial = "balance_financiero.pdf"
imagen_salida = "foto_familiar.png"
clave = "ClaveFinanzas2026"

# 1. Incrustar archivo dentro de la foto
hide_file(
    carrier_image_path=imagen_portadora,
    file_to_hide_path=archivo_confidencial,
    output_image_path=imagen_salida,
    password=clave
)
print("Archivo incrustado de forma invisible.")

# 2. Extraer el archivo en una carpeta de destino
archivo_restaurado, nombre_original = extract_file(
    stego_image_path=imagen_salida,
    output_dir="./documentos_recuperados",
    password=clave
)
print(f"Archivo restaurado como '{nombre_original}' en: {archivo_restaurado}")
```

---

### Ejemplo 3: Consultar la Capacidad de Almacenamiento de una Imagen

```python
from encryptorx import get_image_capacity

info = get_image_capacity("paisaje.png")
print(f"Dimensiones: {info['width']} x {info['height']}")
print(f"Canales LSB útiles: {info['usable_channels']}")
print(f"Capacidad máxima de datos: {info['net_capacity_bytes']:,} bytes (~{info['net_capacity_bytes'] // 1024} KB)")
print(f"Evaluación de Sigilo: {info['stealth_recommendation']}")
```

---

## 7. Uso desde la Línea de Comandos (CLI)

El módulo puede invocarse directamente desde la terminal con `python -m encryptorx.stego`:

### Ocultar texto:
```bash
python -m encryptorx.stego hide-text -i foto.png -t "Mensaje secreto" -o foto_segura.png -p "Clave123"
```

### Extraer texto:
```bash
python -m encryptorx.stego extract-text -i foto_segura.png -p "Clave123"
```

### Ocultar un archivo:
```bash
python -m encryptorx.stego hide-file -i foto.png -f informe.pdf -o foto_segura.png -p "Clave123"
```

### Extraer un archivo:
```bash
python -m encryptorx.stego extract-file -i foto_segura.png -o ./descargas -p "Clave123"
```

### Ver capacidad de una imagen:
```bash
python -m encryptorx.stego info -i foto.png
```

### Evaluar calidad y distorsión (PSNR/MSE):
```bash
python -m encryptorx.stego metrics -orig foto.png -stego foto_segura.png
```

---

## 8. Consideraciones Operativas de Seguridad (OpSec)

1. **Formatos sin pérdida obligatorios**: La imagen resultante debe guardarse siempre en formatos sin compresión destructiva (**PNG** o **BMP**). El formato JPEG comprime mediante la Transformada Discreta del Coseno (DCT), descartando altas frecuencias y alterando los bits LSB, lo que destruiría la información incrustada.
2. **Preservación de Transparencia (Canal Alfa)**: En imágenes PNG con transparencia (modo `RGBA`), el motor solo modifica los canales Rojo, Verde y Azul. El canal Alfa se deja intacto al 100%, evitando artefactos visuales en zonas translúcidas.
3. **Plataformas de Redes Sociales**: Servicios como WhatsApp, Facebook o Twitter recomprimen y convierten automáticamente las imágenes subidas a JPEG de baja calidad. Para transmitir imágenes esteganográficas por internet sin que se dañen los datos, deben enviarse como **"Archivo / Documento" sin comprimir** o a través de correo electrónico, mensajería P2P o nubes de almacenamiento (Google Drive, Dropbox, etc.).
4. **Resistencia a Ataques de Fuerza Bruta**: Con PBKDF2 fijado en 100.000 iteraciones y una sal única de 128 bits para cada imagen, un atacante requeriría miles de años de cómputo para intentar adivinar una contraseña de longitud adecuada mediante fuerza bruta.

---

## 9. Arquitectura Orientada a Objetos (`StegoEngine`)

Para flujos de trabajo avanzados, procesamiento por lotes o configuración de perfiles predeterminados, la biblioteca expone la clase `StegoEngine`:

```python
from encryptorx import StegoEngine

# Instanciar motor configurado para ultra-sigilo en el canal Azul
engine = StegoEngine(
    bits_per_channel=1,
    channels="B",
    shuffle_algorithm="lcg",
    compress=True,
    compression_level=9,
    pbkdf2_rounds=100_000
)

# Ocultar y extraer archivos o texto usando la misma instancia
engine.hide_file("paisaje.png", "contrato.pdf", "paisaje_seguro.png", password="Clave")
archivo_recuperado, nombre = engine.extract_file("paisaje_seguro.png", output_dir="./descargas", password="Clave")
```

---

## 10. Documento Oficial en Formato PDF

Se incluye en el repositorio la especificación técnica completa en formato PDF de alta calidad editorial:
- **Archivo**: [`EncryptorX_Steganography_Specification.pdf`](./EncryptorX_Steganography_Specification.pdf)
- **Generador**: `build_specification_pdf.py` (motor ReportLab).
- **Contenido**: Diagramas de protocolos, demostración matemática formal del teorema de Hull-Dobell, análisis espectral de frecuencias foveales (conos S), tablas de matrices de capacidad vs. PSNR para resoluciones 512x512, Full HD 1080p y 4K UHD, y manual completo para desarrolladores.

