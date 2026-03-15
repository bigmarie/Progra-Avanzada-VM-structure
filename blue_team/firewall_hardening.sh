sudo ufw --force reset
 
# Politicas por defecto
sudo ufw default deny incoming
sudo ufw default allow outgoing
 
# Permitir SSH con limite anti brute-force
sudo ufw limit 22/tcp
 
# Bloquear puertos peligrosos
sudo ufw deny 23    # Telnet
sudo ufw deny 21    # FTP
sudo ufw deny 3389  # RDP
sudo ufw deny 445   # SMB
 
# Activar y mostrar estado
sudo ufw --force enable
sudo ufw status verbose
