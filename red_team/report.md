# Reporte Final

## Metodologia de ataque

La metodologia del Red Team se basa en cuatro frentes principales observados en los scripts del proyecto.

1. Reconocimiento de servicios.
   `scanner.py` se utiliza para identificar puertos abiertos, protocolos y servicios activos en la maquina objetivo. Esta fase permite ubicar los puntos de entrada mas relevantes.

2. Validacion de acceso remoto.
   `ssh_brute.py` realiza pruebas de autenticacion SSH usando multiples llaves privadas. El objetivo es comprobar si existe alguna credencial que permita acceso no autorizado al sistema.

3. Generacion de trafico de prueba.
   `packet_attack.py` construye y envia paquetes ICMP, UDP y TCP con parametros personalizados. Esto permite observar la respuesta del sistema ante trafico manual y verificar el comportamiento de servicios o filtros de red.

4. Manipulacion de trafico en red local.
   `arp_spoofing.py` implementa una tecnica de suplantacion ARP dentro de un segmento de red compartido. Su finalidad es alterar temporalmente la asociacion entre direcciones IP y MAC para desviar trafico dentro de la red local del laboratorio.

## Medidas de remediacion

Las medidas de remediacion deben orientarse a limitar la exposicion de servicios, fortalecer la autenticacion y mejorar la deteccion de eventos sospechosos.

1. Proteger el acceso SSH.
   Restringir usuarios autorizados, revisar las llaves configuradas en `authorized_keys`, reemplazar llaves comprometidas y limitar el acceso al puerto 22 con reglas de firewall. `alert_logger.py` ayuda a detectar accesos exitosos e intentos fallidos.

2. Reducir superficie expuesta.
   Cerrar puertos innecesarios, deshabilitar servicios no requeridos y revisar periodicamente procesos y puertos abiertos. `os_audit.py` apoya esta tarea al inspeccionar configuraciones, servicios y exposicion del sistema.

3. Detectar trafico anomalo.
   Monitorear patrones compatibles con escaneo o inundacion y registrar eventos sospechosos para su analisis. `sniffer_defense.py` aporta deteccion basica sobre trafico TCP y permite aplicar bloqueo por IP.

4. Endurecer el firewall.
   Aplicar una politica restrictiva de trafico entrante, permitir solo puertos necesarios y limitar servicios sensibles como SSH. `firewall_hardening.sh` establece esta base mediante reglas de `ufw`.

5. Mitigar riesgos en la red local.
   Reducir redes planas, aislar sistemas sensibles y monitorear cambios anormales en asociaciones IP-MAC. Esto disminuye el impacto potencial de tecnicas como la suplantacion ARP dentro del laboratorio.
