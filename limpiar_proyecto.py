# limpiar_proyecto.py
# © 2025 ghostmoai. Todos los derechos reservados.
import os
import shutil
from pathlib import Path

# --- CONFIGURACIÓN ---
# Directorio del proyecto (la carpeta donde se encuentra este script)
PROYECTO_DIR = Path(__file__).parent.resolve()

# Lista de archivos y carpetas que se consideran "esenciales" y NO se eliminarán.
# Puedes añadir aquí cualquier otro archivo o carpeta que quieras conservar.
ARCHIVOS_ESENCIALES = [
    # Scripts principales
    "EncryptorX.py",
    "installer.py",
    "copilador_V2.py",
    
    # Este mismo script de limpieza
    "limpiar_proyecto.py",

    # Recursos para la compilación
    "version_info.txt",
    "163290-logotipo_de_piton-piton-icono-lenguaje_de_programacion-logotipo-3840x2160.ico",
    "Licencia Pública – EncryptorX.txt",

    # Datos de la aplicación
    "key.key",

    # Carpetas importantes mencionadas
    "dist",
    "no basura",

    # Es común mantener la configuración del control de versiones y del editor
    ".git",
    ".gitignore",
    ".vscode",
]

def limpiar_directorio():
    """
    Recorre el directorio del proyecto y elimina todos los archivos y carpetas
    que no estén en la lista de ARCHIVOS_ESENCIALES.
    """
    print(f"--- Limpiando el directorio: {PROYECTO_DIR} ---")
    
    elementos_a_eliminar = []
    
    # 1. Identificar todos los elementos que no son esenciales
    for elemento in PROYECTO_DIR.iterdir():
        if elemento.name not in ARCHIVOS_ESENCIALES:
            elementos_a_eliminar.append(elemento)

    if not elementos_a_eliminar:
        print("\n[INFO] No se encontró basura. El directorio ya está limpio.")
        return

    # 2. Mostrar al usuario lo que se va a eliminar y pedir confirmación
    print("\nSe eliminarán los siguientes archivos y carpetas:")
    for elemento in elementos_a_eliminar:
        tipo = "Carpeta" if elemento.is_dir() else "Archivo"
        print(f"  - {elemento.name} ({tipo})")
    
    print("-" * 20)
    respuesta = input("¿Estás seguro de que deseas continuar? (s/n): ").lower().strip()

    if respuesta != 's':
        print("\nLimpieza cancelada por el usuario.")
        return

    # 3. Proceder con la eliminación
    print("\n[*] Iniciando limpieza...")
    for elemento in elementos_a_eliminar:
        try:
            if elemento.is_dir(): shutil.rmtree(elemento)
            else: elemento.unlink()
            print(f"  [OK] Elemento eliminado: {elemento.name}")
        except Exception as e:
            print(f"  [ERROR] No se pudo eliminar {elemento.name}: {e}")
            
    print("\n--- Limpieza Finalizada ---")

if __name__ == "__main__":
    limpiar_directorio()
    input("\nPresiona Enter para salir.")