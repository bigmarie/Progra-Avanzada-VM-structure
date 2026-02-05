#!/bin/bash

sudo ufw --force reset

sudo ufw default deny incoming

sudo ufw default allow outgoing


# 3. Permitir SSH (Puerto 22) - Solo lo esencial

sudo ufw allow 22/tcp


# Necesario para que el Red Team ataque y el Blue Team monitoree

sudo ufw allow 8080/tcp


# 5. Permitir ICMP (Ping) para diagnóstico del laboratorio

sudo ufw allow icmp


# 6. Habilitar el firewall

sudo ufw --force enable


# 7. Mostrar estado final

sudo ufw status verbose
