#!/usr/bin/env python3
# Blue Team - Alert Logger
# Proyecto Final - Azure Lab

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

    with open(ARCHIVO_LOG, "a") as f:
        f.write(linea)

def monitorear():
    print("Monitoreando eventos de autenticacion...")
    print(f"Alertas se guardan en: {ARCHIVO_LOG}")
    print("Presiona Ctrl+C para detener.\n")

    # Monitorear tanto ssh como sshd
    proceso = subprocess.Popen(
        ["journalctl", "-t", "sshd", "-f", "-n", "0", "--no-pager"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for linea in proceso.stdout:
        linea = linea.strip()

        if "Accepted password" in linea or "Accepted publickey" in linea:
            registrar_alerta("ACCESO EXITOSO", linea)

        elif "Failed password" in linea:
            registrar_alerta("INTENTO FALLIDO", linea)

        elif "Invalid user" in linea:
            registrar_alerta("USUARIO INVALIDO", linea)

        elif "session closed" in linea:
            registrar_alerta("SESION CERRADA", linea)

        elif "session opened" in linea:
            registrar_alerta("SESION ABIERTA", linea)

# --- Inicio ---
try:
    monitorear()
except KeyboardInterrupt:
    print("\nMonitoreo detenido.")
