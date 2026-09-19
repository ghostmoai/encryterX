# installer.py
# © 2025 ghostmoai. Todos los derechos reservados.
import os
import sys
import shutil
import ctypes
import subprocess
import winreg
import argparse
from pathlib import Path

# pywin32 es necesario para leer la versión del .exe
try:
    from win32api import GetFileVersionInfo, LOWORD, HIWORD
except ImportError:
    print("[ERROR] El módulo 'pywin32' es necesario para esta función.")
    print("        Por favor, instálalo con: pip install pywin32")
    input("\nPresiona Enter para salir.")
    sys.exit(1)

# =========================
#  CONFIGURACIÓN
# =========================
APP_NAME = "EncryptorX"
EXE_NAME = "EncryptorX.exe"
LICENSE_NAME = "Licencia Pública – EncryptorX.txt"

# Solo para Windows
if os.name != "nt":
    print("Este instalador es solo para Windows.")
    input("Presiona Enter para salir.")
    sys.exit(1)

# Rutas importantes
# El directorio de instalación será una carpeta llamada como la app,
# creada en el mismo lugar donde se ejecuta el instalador.
INSTALL_DIR = Path(sys.executable).parent / APP_NAME if getattr(sys, 'frozen', False) else Path(__file__).parent / "dist" / APP_NAME

# =========================
#  UTILIDADES DE SISTEMA
# =========================
def get_base_path():
    """Obtiene la ruta base donde se encuentran los archivos de datos empaquetados."""
    if getattr(sys, 'frozen', False):
        # Si estamos en un ejecutable de PyInstaller, los datos empaquetados
        # con --add-data se extraen a una carpeta temporal accesible vía sys._MEIPASS.
        return Path(sys._MEIPASS)
    else:
        # Si se ejecuta como script, los archivos de datos están en el directorio
        return Path(__file__).parent

def get_version_from_exe(exe_path: Path) -> str:
    """
    Lee la versión del archivo desde los metadatos de un .exe usando pywin32.
    Devuelve una cadena como "1.2.2.0" o "0.0.0.0" si falla.
    """
    if not exe_path.exists():
        return "0.0.0.0"
    try:
        info = GetFileVersionInfo(str(exe_path), '\\')
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return f"{HIWORD(ms)}.{LOWORD(ms)}.{HIWORD(ls)}.{LOWORD(ls)}"
    except Exception:
        return "0.0.0.0" # Fallback si no se puede leer la versión

def get_desktop_path_from_registry():
    """Obtiene la ruta del escritorio desde el registro de Windows. Es más fiable que '~/Desktop'."""
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            # Leemos el valor 'Desktop' del registro
            desktop_raw, _ = winreg.QueryValueEx(key, "Desktop")
        # El valor puede contener variables de entorno como %USERPROFILE%, así que las expandimos
        return Path(os.path.expandvars(desktop_raw))
    except Exception:
        # Si por alguna razón falla, usamos el método tradicional como fallback
        return Path(os.path.expanduser("~/Desktop"))

DESKTOP_DIR = get_desktop_path_from_registry()
START_MENU_DIR = Path(os.path.expanduser("~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs")) / APP_NAME

def add_to_path(path_to_add: Path):
    """Añade un directorio al PATH del usuario de forma permanente."""
    print(f"[*] Añadiendo '{path_to_add}' al PATH del usuario...")
    try:
        # HKEY_CURRENT_USER\Environment
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
            current_path, _ = winreg.QueryValueEx(key, "Path")
            if str(path_to_add) not in current_path.split(';'):
                new_path = f"{current_path};{str(path_to_add)}"
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                # Notificar a otros procesos del cambio
                ctypes.windll.user32.SendMessageW(0xFFFF, 0x001A, 0, "Environment")
                print("[+] PATH actualizado con éxito.")
    except Exception as e:
        print(f"[!] Error al modificar el PATH: {e}")

def remove_from_path(path_to_remove: Path):
    """Elimina un directorio del PATH del usuario."""
    print(f"[*] Eliminando '{path_to_remove}' del PATH...")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
            current_path, _ = winreg.QueryValueEx(key, "Path")
            paths = [p for p in current_path.split(';') if p and Path(p) != path_to_remove]
            new_path = ';'.join(paths)
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            ctypes.windll.user32.SendMessageW(0xFFFF, 0x001A, 0, "Environment")
            print("[+] PATH limpiado con éxito.")
    except Exception as e:
        print(f"[!] Error al limpiar el PATH: {e}")

def create_shortcut(target: Path, shortcut_path: Path):
    """Crea un acceso directo usando PowerShell para evitar dependencias."""
    print(f"[*] Creando acceso directo en '{shortcut_path}'...")

    # Escapar comillas simples en las rutas para PowerShell, que romperían el string.
    ps_target = str(target).replace("'", "''")
    ps_shortcut_path = str(shortcut_path).replace("'", "''")
    ps_working_dir = str(target.parent).replace("'", "''")

    ps_command = f"""
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('{ps_shortcut_path}')
    $Shortcut.TargetPath = '{ps_target}'
    $Shortcut.WorkingDirectory = '{ps_working_dir}'
    $Shortcut.IconLocation = '{ps_target}'
    $Shortcut.Save()
    """
    try:
        # Se añaden flags a PowerShell para una ejecución más robusta y predecible.
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            check=True, capture_output=True)
        print(f"[+] Acceso directo creado.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al crear acceso directo: {e.stderr.decode('cp850', errors='ignore')}")

def register_uninstaller(uninstaller_path: Path, install_path: Path, app_version: str):
    """Registra la aplicación en 'Agregar o quitar programas'."""
    print("[*] Registrando desinstalador...")
    uninstall_cmd = f'"{uninstaller_path}" --uninstall'
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{key_path}\\{APP_NAME}") as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            # El comando de desinstalación ahora apunta al EXE principal con el argumento --uninstall
            uninstall_command = f'"{install_path / EXE_NAME}" --uninstall'
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall_command)
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(install_path / EXE_NAME))
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "ghostmoai")
            if app_version != "0.0.0.0":
                winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, app_version)
        print("[+] Desinstalador registrado.")
    except Exception as e:
        print(f"[!] Error al registrar el desinstalador: {e}")

# =========================
#  LÓGICA DE INSTALACIÓN
# =========================
def install(args: argparse.Namespace):
    """Ejecuta el proceso de instalación completo."""
    print(f"\n--- Instalando {APP_NAME} ---")

    # --- Lógica de búsqueda mejorada para los archivos a instalar ---
    base_path = get_base_path()
    print(f"[*] Buscando archivos de instalación...")
    
    # Cuando está compilado, los archivos están en la raíz de _MEIPASS.
    # Cuando se ejecuta como script, se espera que estén en la carpeta 'dist'.
    if getattr(sys, 'frozen', False):
        source_dir = base_path
    else:
        source_dir = base_path / "dist"

    exe_to_install = source_dir / EXE_NAME

    # 1. Verificar que el .exe a instalar existe
    if not exe_to_install.is_file():
        print(f"\n[ERROR] No se pudo encontrar el archivo principal '{EXE_NAME}'.")
        if getattr(sys, 'frozen', False):
            print(f"         El instalador esperaba encontrarlo empaquetado dentro de sí mismo, pero no fue así.")
            print(f"         Asegúrate de compilar el instalador con el argumento --add-data.")
        else:
            print(f"         El instalador (en modo desarrollo) buscó en: '{source_dir}'")
            print(f"         Ejecuta primero el script de compilación para generar '{EXE_NAME}'.")
        input("\nPresiona Enter para salir.")
        sys.exit(1)

    # La licencia se busca en la misma carpeta donde se encontró el ejecutable.
    license_to_install = source_dir / LICENSE_NAME
    print(f"[+] Archivos de instalación encontrados en: '{source_dir}'")

    # 1.2. Leer la versión desde el ejecutable
    app_version = get_version_from_exe(exe_to_install)
    print(f"[*] Versión de la aplicación detectada: {app_version}")

    # 1.5. Mostrar y aceptar licencia
    if license_to_install.exists():
        if not args.yes:
            print("\n--- Licencia de Uso ---")
            try:
                # Se intenta leer y mostrar el contenido de la licencia
                with open(license_to_install, "r", encoding="utf-8", errors="ignore") as f:
                    print(f.read())
            except Exception as e:
                print(f"[!] No se pudo mostrar el archivo de licencia: {e}")
            
            print("-" * 23)
            respuesta = input("¿Aceptas los términos de la licencia para continuar? (s/n): ").lower().strip()
            if respuesta != 's':
                print("\nInstalación cancelada por el usuario.")
                sys.exit(0)
        else:
            print("[*] Aceptando licencia automáticamente (modo no interactivo).")

    # 2. Crear directorios
    print(f"[*] Creando directorios en '{INSTALL_DIR}'...")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    START_MENU_DIR.mkdir(parents=True, exist_ok=True)

    # 3. Copiar archivos
    print("[*] Copiando archivos de la aplicación...")
    # shutil.copy2 crea una copia exacta, preservando metadatos como la fecha y permisos.
    shutil.copy2(exe_to_install, INSTALL_DIR / EXE_NAME)
    if license_to_install.exists():
        shutil.copy2(license_to_install, INSTALL_DIR / LICENSE_NAME)

    # 4. Añadir al PATH
    add_to_path(INSTALL_DIR)

    # 5. Crear accesos directos
    final_exe_path = INSTALL_DIR / EXE_NAME
    create_shortcut(final_exe_path, DESKTOP_DIR / f"{APP_NAME}.lnk")
    create_shortcut(final_exe_path, START_MENU_DIR / f"{APP_NAME}.lnk")

    # 6. Registrar en "Agregar o quitar programas"
    #    El desinstalador es ahora la propia aplicación con el flag --uninstall
    register_uninstaller(final_exe_path, INSTALL_DIR, app_version)

    print(f"\n[ÉXITO] {APP_NAME} se ha instalado correctamente.")
    print(f"Puedes ejecutarlo desde el acceso directo o escribiendo '{EXE_NAME.split('.')[0]}' en una nueva terminal.")

    # 7. Secuencia de auto-eliminación del instalador
    if getattr(sys, 'frozen', False):
        print("[*] Finalizando y limpiando el instalador...")
        temp_dir = Path(os.environ["TEMP"])
        batch_file = temp_dir / f"cleanup_{APP_NAME}.bat"
        original_setup_exe = Path(sys.executable)

        batch_content = f"""
@echo off
echo.
echo Limpiando archivos de instalacion...
:: Espera a que el proceso del instalador termine
timeout /t 2 /nobreak > nul
:: Elimina el instalador original
del "{original_setup_exe}"
:: Elimina este script
(goto) 2>nul & del "%~f0"
"""
        try:
            with open(batch_file, "w") as f:
                f.write(batch_content)
            # Ejecutar el .bat de forma desvinculada para que pueda eliminar el .exe original
            subprocess.Popen(f'"{batch_file}"', shell=True, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        except Exception as e:
            print(f"[!] No se pudo iniciar la auto-eliminación del instalador: {e}")
            print(f"    Puedes eliminar manualmente el archivo: {original_setup_exe}")

# =========================
#  PUNTO DE ENTRADA
# =========================
def main():
    parser = argparse.ArgumentParser(description=f"Instalador/Desinstalador para {APP_NAME}")
    parser.add_argument("--uninstall", action="store_true", help="Desinstala la aplicación.")
    parser.add_argument("-y", "--yes", action="store_true", help="Acepta automáticamente todas las solicitudes (modo no interactivo).")
    args = parser.parse_args()

    if args.uninstall:
        # La lógica de desinstalación ahora reside en el programa principal (EncryptorX.exe)
        # Este script (setup.exe) solo debe instalar.
        print("[ERROR] Este ejecutable es solo para instalar la aplicación.")
        print(f"        Para desinstalar, usa 'Agregar o quitar programas' o ejecuta el comando:")
        print(f'        "{INSTALL_DIR / EXE_NAME}" --uninstall')
        sys.exit(1)
    else:
        install(args)
    
if __name__ == "__main__":
    main()
