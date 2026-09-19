@echo off
title EncryptorX - Motor Criptografico Nativo Rust v3.0.0
cd /d "%~dp0"
if exist "EncryptorX.exe" (
    start "" "EncryptorX.exe"
) else (
    echo [ERROR] No se encontro EncryptorX.exe.
    pause
)
