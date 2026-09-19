"""
This module handles the compilation of the EncryptorX application and its installer
using PyInstaller.
"""
# © 2025 ghostmoai. Todos los derechos reservados.
import subprocess
import os
import sys
import shutil
from pathlib import Path

# Directorio base del script, para que funcione sin importar desde dónde se ejecute
SCRIPT_DIR = Path(__file__).parent.resolve()

# =========================
#  CONFIGURACIÓN DE COMPILACIÓN
# =========================
APP_NAME = "EncryptorX"
APP_SCRIPT = "EncryptorX.py"
INSTALLER_SCRIPT = "installer.py"
ICON_FILE = "163290-logotipo_de_piton-piton-icono-lenguaje_de_programacion-logotipo-3840x2160.ico"  # Icono para la aplicación principal (EncryptorX.exe)
INSTALLER_ICON_FILE = "163290-logotipo_de_piton-piton-icono-lenguaje_de_programacion-logotipo-3840x2160.ico" # Icono para el instalador (setup.exe)
VERSION_INFO_FILE = "version_info.txt" # Archivo con copyright y versión para el .exe
LICENSE_NAME = "Licencia Pública – EncryptorX.txt"

APP_EXE_NAME = "EncryptorX"
INSTALLER_EXE_NAME = "setup"

# Usar rutas absolutas para los directorios de salida y trabajo
DIST_DIR = SCRIPT_DIR / "dist"
BUILD_DIR = SCRIPT_DIR / "build"

def compile_with_pyinstaller(script_path: Path, exe_name: str, icon_file: Path, is_windowed: bool = False, use_uac: bool = False, extra_data: list = None):
    """Función genérica para compilar un script con PyInstaller."""
    print(f"\n>>> Compilando {script_path.name} en {exe_name}.exe...")

    if not script_path.is_file():
        print(f"[ERROR] El archivo de script '{script_path.name}' no se encontró en la ruta: {script_path}")
        return False
    
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--name", exe_name,
        # Especificar directorios de salida para evitar desorden
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
    ]
    
    if is_windowed:
        command.append("--windowed")
    
    if use_uac:
        command.append("--uac-admin")
        
    # Añadir información de versión y copyright desde el archivo
    version_file_path = SCRIPT_DIR / VERSION_INFO_FILE
    if version_file_path.is_file():        command.extend(["--version-file", str(version_file_path)])
    else:
        print(f"    [AVISO] Archivo de versión '{VERSION_INFO_FILE}' no encontrado. No se añadirá copyright al .exe.")

    if icon_file and icon_file.is_file():
        command.extend(["--icon", str(icon_file)])
    else:
        print(f"    [AVISO] Archivo de icono '{icon_file.name}' no encontrado. Se usará el icono por defecto.")

    # Añadir datos adicionales (como otros .exe o archivos) al paquete
    if extra_data:
        for data_item in extra_data:
            command.extend(["--add-data", data_item])

    command.append(str(script_path))
    
    print(f"    Comando: {' '.join(command)}")
    
    try:
        # Usamos Popen para mostrar la salida en tiempo real, lo que es mejor para procesos largos.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
        for line in iter(process.stdout.readline, ''):
            print(f"    {line.strip()}")
        process.wait()
        
        if process.returncode != 0:
            print(f"[ERROR] PyInstaller falló con código de error {process.returncode}.")
            return False
            
        print(f"[ÉXITO] '{exe_name}.exe' creado en la carpeta '{DIST_DIR}'.")
        return True
        
    except FileNotFoundError:
        print("[ERROR] El comando 'pyinstaller' no se encontró.")
        print("         Asegúrate de tener PyInstaller instalado: pip install pyinstaller")
        return False
    except Exception as e:
        print(f"[ERROR] Ocurrió un error inesperado durante la compilación: {e}")
        return False

def main():
    """Script principal para compilar la aplicación y el instalador."""
    print("--- Iniciando proceso de compilación para EncryptorX ---")

    # 1. Limpiar compilaciones anteriores para empezar desde cero.
    print("\n>>> Limpiando artefactos de compilaciones anteriores...")
    try:
        if DIST_DIR.exists():
            shutil.rmtree(DIST_DIR)
            print(f"    [OK] Directorio '{DIST_DIR.name}' eliminado.")
        if BUILD_DIR.exists():
            shutil.rmtree(BUILD_DIR)
            print(f"    [OK] Directorio '{BUILD_DIR.name}' eliminado.")
    except Exception as e:
        print(f"    [ERROR] No se pudo limpiar los directorios: {e}")
        sys.exit(1)

    # Definir rutas absolutas a los archivos de origen
    app_script_path = SCRIPT_DIR / APP_SCRIPT
    installer_script_path = SCRIPT_DIR / INSTALLER_SCRIPT
    
    # Definir rutas a los iconos
    app_icon = SCRIPT_DIR / ICON_FILE
    installer_icon = SCRIPT_DIR / INSTALLER_ICON_FILE

    # 2. Compilar la aplicación principal (EncryptorX.py)
    #    --windowed: Para que no abra una consola al hacer doble clic.
    #    El propio script se encarga de 'engancharse' a una consola si se ejecuta desde ella.
    if not compile_with_pyinstaller(app_script_path, APP_EXE_NAME, app_icon, is_windowed=True, use_uac=False):
        sys.exit(1)

    # 3. Definir los archivos que se empaquetarán DENTRO del instalador.
    #    La sintaxis es "origen;destino_dentro_del_paquete". El punto '.' significa la raíz.
    data_to_bundle = []
    app_exe_path_in_dist = DIST_DIR / f"{APP_EXE_NAME}.exe"
    if app_exe_path_in_dist.exists():
        data_to_bundle.append(f"{app_exe_path_in_dist}{os.pathsep}.")
    else:
        print(f"[ERROR] No se encontró '{app_exe_path_in_dist}' para empaquetar en el instalador.")
        sys.exit(1)

    license_path = SCRIPT_DIR / LICENSE_NAME
    if license_path.exists():
        data_to_bundle.append(f"{license_path}{os.pathsep}.")
    else:
        print(f"[AVISO] Archivo de licencia no encontrado. No se incluirá en el instalador.")

    # 4. Compilar el instalador (installer.py)
    #    Este es un script de consola, por lo que 'is_windowed' es False.
    #    No necesita UAC porque instala en el perfil del usuario.
    if not compile_with_pyinstaller(installer_script_path, INSTALLER_EXE_NAME, installer_icon, is_windowed=False, use_uac=False, extra_data=data_to_bundle):
        sys.exit(1)

    # 5. Limpiar archivos temporales finales de PyInstaller
    print("\n>>> Limpiando archivos de compilación temporales...")
    if BUILD_DIR.exists(): shutil.rmtree(BUILD_DIR)
    for spec_file in SCRIPT_DIR.glob("*.spec"): spec_file.unlink()
    print("    [OK] Archivos temporales eliminados.")

    print("\n--- Proceso de compilación finalizado ---")
    print(f"Tus archivos de distribución están listos en la carpeta '{DIST_DIR}'.")
    print(f"\n- Para nuevos usuarios: Distribuye '{INSTALLER_EXE_NAME}.exe'. Contiene todo y se auto-eliminará después de la instalación.")
    print(f"- Para actualizaciones: Sube '{APP_EXE_NAME}.exe' a los 'Assets' de tu release en GitHub.")

if __name__ == "__main__":
    main()
