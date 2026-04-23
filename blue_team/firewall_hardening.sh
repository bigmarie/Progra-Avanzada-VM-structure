#!/bin/bash
echo "Iniciando Hardening del Firewall (Blue Team)..."

# 1. Resetear reglas previas para evitar conflictos
sudo ufw --force reset

sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2. Permitir SSH con rate-limit (bloquea mas de 6 intentos en 30s)
sudo ufw limit 22/tcp

# 3. Bloquear puertos peligrosos
sudo ufw deny 23    # Telnet
sudo ufw deny 21    # FTP
sudo ufw deny 3389  # RDP

# 4. Abrir puerto del Honeypot
sudo ufw allow 8080/tcp

# 5. Habilitar firewall y mostrar estado
sudo ufw --force enable
sudo ufw status verbose

# 6. Cambio de puerto SSH 22 -> 2244
# sudo sed -i 's/#Port 22/Port 2244/' /etc/ssh/sshd_config
# sudo systemctl restart ssh
sudo ufw limit 2244/tcp
sudo ufw delete limit 22/tcp

echo "Hardening completado exitosamente."
