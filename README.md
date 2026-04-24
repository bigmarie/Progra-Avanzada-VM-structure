# Progra-Avanzada-VM-structure

Este repositorio es para el almacenamiento de la estructura de archivos de las máquinas virtuales para el proyecto de programación avanzada (CY202).

## Descripción

El objetivo de este laboratorio es el diseñar y desplegar un entorno realista en Microsoft Azure, donde los estudiantes puedan actuar en roles de `Red Team (atacante)` y `Blue Team (defensor)`.

Cada equipo deberá desarrollar y aplicar herramientas escritas en `Python` para atacar y defender una **máquina virtual (VM)** específica dentro de Azure, utilizando técnicas de auditoría, escaneo, análisis de tráfico y ataques controlados.

## Roles

### Blue Team (🔵)

Este equipo de 2 estudiantes se encarga de la auditoría, endurecimiento (hardening) y monitoreo de la VM. Específicamente el `Blue Team` se encarga de desarrollar scripts en Python que:

- Detecten intentos de escaneo y tráfico sospechoso (`scapy/sniffer`).
- Monitoreen accessos no autorizados (logs de SSH, FT, etc.).
- Realicen hardening del sistema (firewall, usuarios, servicios).
- Automatización de auditoría del sistema operativo (os, subprocess).

Por último, este equipo también se encarga de implementar notificaciones o bloqueos automatizados.

### Red Team (🔴)

Este equipo de 2 estudiantes se encarga del reconocimiento, explotación y reporte de vulnerabilidades. Específicamente el `Red Team` se encargan de desarrollar scripts en Python para:

- Identificar puertos abiertos y servicios de ejecución (`nmap`).
- Capturar paquetes y buscar vulnerabilidades en protocolos (`scapy`).
- Ejecutar ataques de diccionario para intentar acceso no autorizado.
- Ejecutar un ataque ARP Spoofing (crear una máquina virtual en la misma red y ejecutar el ataque desde esa máquina virtual).

Por último, este equipo también se encarga de documentar debilidades encontradas y métodos usados.

## Requisitos

- Python 3.10 o superior instalado en las máquinas virtuales.
- Acceso a las VMs con permisos de administrador o root para ejecutar auditorías, reglas de firewall y ataques de red controlados.
- Paquetes de Python requeridos para cada equipo:
  - `blue_team/requirements.txt`
  - `red_team/requirements.txt`
- Conectividad de red entre las VMs cuando se requiera ejecutar pruebas de ARP spoofing, escaneo de puertos y monitoreo de tráfico.
- Entorno aislado y autorizado: todas las pruebas deben realizarse dentro de la red de laboratorio y con consentimiento del instructor.

## Instrucciones de Ejecución

1. Clonar o copiar el repositorio en cada máquina virtual participante.
2. Instalar las dependencias correspondientes:
   - `cd blue_team && pip install -r requirements.txt`
   - `cd red_team && pip install -r requirements.txt`
3. Para el Blue Team:
   - Ejecutar scripts de auditoría del sistema como `os_audit.py` para generar informes de estado del host.
   - Iniciar el monitoreo del tráfico y detección de intrusiones con `sniffer_defense.py` y `alert_logger.py`.
   - Aplicar hardening de firewall y servicios utilizando `firewall_hardening.sh`.
   - Revisar los registros generados en tiempo real para detectar accesos sospechosos.
4. Para el Red Team:
   - Ejecutar el escaneo de puertos y servicios con `scanner.py` para identificar objetivos y posibles vectores.
   - Probar ataques de fuerza bruta contra servicios SSH con `ssh_brute.py` en entornos autorizados.
   - Emplear `arp_spoofing.py` y `packet_attack.py` para evaluar la detección de ataques de red y la resistencia de la infraestructura.
   - Documentar los resultados y evidencias en `report.md`.
5. Siempre ejecutar los scripts desde el directorio correspondiente y con la sintaxis adecuada de Python:
   - `python blue_team/os_audit.py`
   - `python red_team/scanner.py`

## Cómo Evaluar Éxito de Ataques o Defensas

_Para el Blue Team:_

- Éxito parcial: detectar y alertar sobre escaneos, conexiones SSH no autorizadas o actividades de ARP spoofing.
- Éxito completo: bloquear el tráfico malicioso, registrar los eventos relevantes y demostrar que la VM se mantiene segura tras aplicar hardening.
- La defensa se considera eficaz cuando los scripts pueden identificar anomalías y mantener un registro visible de las acciones defensivas.

_Para el Red Team:_

- Éxito parcial: descubrir puertos abiertos, servicios vulnerables o capturar tráfico potencialmente útil dentro del laboratorio.
- Éxito completo: ejecutar ataques controlados que evidencien una brecha de seguridad sin comprometer permanentemente la VM o la red del laboratorio.
- La labor del Red Team se evalúa por la calidad del reconocimiento, la efectividad de las pruebas y la documentación de las debilidades halladas.

## Evaluación general

- La entrega debe incluir evidencia clara de ejecución y resultados para ambos equipos.
- Se valorará la capacidad de explicar qué se hizo, por qué, y cómo se mitigaron o explotaron las vulnerabilidades.
- Todos los scripts y pruebas deben ejecutarse dentro del alcance del laboratorio y respetando las reglas de seguridad establecidas.
