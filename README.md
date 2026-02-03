# Progra-Avanzada-VM-structure
Este repositorio es para el almacenamiento de la estructura de archivos de las máquinas virtuales para el proyecto de programación avanzada (CY202).
## Descripción
El objetivo de este laboratorio es el diseñar y desplegar un entorno realista en Microsoft Azure, donde los estudiantes puedan actuar en roles de `Red Team (atacante)` y `Blue Team (defensor)`.

Cada equipo deberá desarrollar y aplicar herramientas escritas en `Python` para atacar y defender una **máquina virtual (VM)** específica dentro de Azure, utilizando técnicas de auditoría, escaneo, análisis de tráfico y ataques controlados.

## Roles
### Blue Team (🔵)
Este equipo de 2 estudiantes se encarga de la auditoría, endurecimiento (hardening) y monitoreo de la VM. Específicamente el `Blue Team` se encarga de desarrollar scripts en Python que:
* Detecten intentos de escaneo y tráfico sospechoso (`scapy/sniffer`).
* Monitoreen accessos no autorizados (logs de SSH, FT, etc.).
* Realicen hardening del sistema (firewall, usuarios, servicios).
* Automatización de auditoría del sistema operativo (os, subprocess).

Por último, este equipo también se encarga de implementar notificaciones o bloqueos automatizados.

### Red Team (🔴)
Este equipo de 2 estudiantes se encarga del reconocimiento, explotación y reporte de vulnerabilidades. Específicamente el `Red Team` se encargan de desarrollar scripts en Python para:
* Identificar puertos abiertos y servicios de ejecución (`nmap`).
* Capturar paquetes y buscar vulnerabilidades en protocolos (`scapy`).
* Ejecutar ataques de diccionario para intentar acceso no autorizado.
* Ejecutar un ataque ARP Spoofing (crear una máquina virtual en la misma red y ejecutar el ataque desde esa máquina virtual).

Por último, este equipo también se encarga de documentar debilidades encontradas y métodos usados.
## Requisitos
## Instrucciones de Ejecución
## Cómo Evaluar Éxito de Ataques o Defensas