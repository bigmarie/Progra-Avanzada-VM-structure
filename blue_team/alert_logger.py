#!/usr/bin/env python3
# ============================================================
# Blue Team - Alert Logger
# Proyecto Final - Azure Lab
#
# Este script monitorea en tiempo real los eventos de acceso
# SSH en la VM y guarda las alertas en un archivo .txt
#
# USO:
#   python3 alert_logger.py         (primer plano)
#   nohup python3 alert_logger.py & (segundo plano)
#
# SALIDA:
#   logs_seguridad/alertas.txt
# ============================================================

import os
import subprocess
from datetime import datetime

CARPETA_LOGS = "logs_seguridad"
ARCHIVO_LOG  = os.path.join(CARPETA_LOGS, "alertas.txt")

# Crear carpeta si no existe
if not os.path.exists(CARPETA_LOGS):
    os.makedirs(CARPETA_LOGS)
    print(f"Carpeta creada: {CARPETA_LOGS}")

def registrar_alerta(tipo, descripcion):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{timestamp}] [{tipo}] {descripcion}\n"

    print(linea.strip())

    # Modo "a" = agregar sin borrar lo anterior
    with open(ARCHIVO_LOG, "a") as f:
        f.write(linea)

def mostrar_historial():
    """
    Al arrancar el script muestra los intentos fallidos
    previos usando journalctl con grep, similar a:
    grep sshd.*Failed /var/log/auth.log
    """
    print("="*50)
    print("HISTORIAL DE INTENTOS FALLIDOS PREVIOS")
    print("="*50)

    resultado = subprocess.run(
        ["journalctl", "-t", "sshd", "--no-pager", "-n", "100"],
        capture_output=True,
        text=True
    )

    encontrados = 0
    for linea in resultado.stdout.splitlines():

        # Intentos fallidos previos
        if "Failed password" in linea:
            print(f"  [INTENTO FALLIDO]   {linea.strip()}")
            encontrados += 1

        # Escaneos de puertos previos (no enviaron identificacion SSH)
        elif "Did not receive identification" in linea:
            print(f"  [ESCANEO DE PUERTO] {linea.strip()}")
            encontrados += 1

    if encontrados == 0:
        print("  Sin intentos fallidos previos.")

    print("="*50)
    print()

def monitorear():
    """
    Lee los eventos de sshd en tiempo real usando journalctl.

    Se usa -t sshd porque Ubuntu etiqueta los eventos SSH
    con el identificador "sshd" (SSH Daemon), que es el proceso
    que corre en segundo plano escuchando el puerto 22.

    Flags de journalctl:
      -t sshd    : filtrar por identificador sshd
      -f         : modo tiempo real (como tail -f)
      -n 0       : no mostrar historial, solo eventos nuevos
      --no-pager : evitar paginacion en la salida
    """
    print("Monitoreando eventos de autenticacion en tiempo real...")
    print(f"Alertas se guardan en: {ARCHIVO_LOG}")
    print("Presiona Ctrl+C para detener.\n")

    proceso = subprocess.Popen(
        ["journalctl", "-t", "sshd", "-f", "-n", "0", "--no-pager"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for linea in proceso.stdout:
        linea = linea.strip()

        # Alguien entro correctamente (contrasena o llave SSH)
        if "Accepted password" in linea or "Accepted publickey" in linea:
            registrar_alerta("ACCESO EXITOSO", linea)

        # Contrasena incorrecta
        elif "Failed password" in linea:
            registrar_alerta("INTENTO FALLIDO", linea)

        # Usuario que no existe en el sistema
        elif "Invalid user" in linea:
            registrar_alerta("USUARIO INVALIDO", linea)

        # Sesion cerrada (alguien se desconecto)
        elif "session closed" in linea:
            registrar_alerta("SESION CERRADA", linea)

        # Sesion abierta (alguien entro exitosamente)
        elif "session opened" in linea:
            registrar_alerta("SESION ABIERTA", linea)

        # Escaneo de puertos (conecto al puerto 22 pero no intento login)
        elif "Did not receive identification" in linea:
            registrar_alerta("ESCANEO DE PUERTO", linea)

# --- Inicio ---
try:
    mostrar_historial()
    monitorear()
except KeyboardInterrupt:
    print("\nMonitoreo detenido.")
