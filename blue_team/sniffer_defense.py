#!/usr/bin/env python3

import argparse
import logging
import signal
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Set, Tuple

from scapy.all import sniff, IP, TCP  # type: ignore


DEFAULT_INTERFACE = None  # Scapy usará la interfaz por defecto si es None

# Umbrales educativos, no “perfectos”
SYN_FLOOD_WINDOW_SECONDS = 10
SYN_FLOOD_THRESHOLD = 30

ACK_SCAN_WINDOW_SECONDS = 10
ACK_SCAN_THRESHOLD = 20

# Puertos comunes permitidos. Todo lo demás se puede marcar como "inusual"
COMMON_PORTS: Set[int] = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 514, 587, 631, 636, 873, 989,
    990, 993, 995, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375,
    2376, 3000, 3306, 3389, 5000, 5432, 5672, 5900, 5984, 6379, 6443, 8000,
    8080, 8081, 8443, 9000, 9200, 9300, 11211, 27017
}

LOG_FILE = "sniffer_defense.log"

# Conteo de SYN por IP origen dentro de una ventana
syn_activity: Dict[str, Deque[float]] = defaultdict(deque)

# Conteo de ACK por IP origen dentro de una ventana
ack_activity: Dict[str, Deque[float]] = defaultdict(deque)

# Puertos tocados por IP para detectar comportamiento tipo scan
ack_ports_seen: Dict[str, Dict[int, float]] = defaultdict(dict)

# Para no repetir alertas constantemente
recent_alerts: Dict[Tuple[str, str], float] = {}

# IPs ya bloqueadas
blocked_ips: Set[str] = set()

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def cleanup_old_entries(activity_deque: Deque[float], window_seconds: int, current_time: float) -> None:
    while activity_deque and (current_time - activity_deque[0] > window_seconds):
        activity_deque.popleft()


def cleanup_old_port_entries(ip: str, window_seconds: int, current_time: float) -> None:
    old_ports = [
        port for port, ts in ack_ports_seen[ip].items()
        if current_time - ts > window_seconds
    ]
    for port in old_ports:
        del ack_ports_seen[ip][port]


def should_rate_limit_alert(src_ip: str, alert_type: str, cooldown: int = 15) -> bool:
    key = (src_ip, alert_type)
    current_time = time.time()
    last_time = recent_alerts.get(key, 0)

    if current_time - last_time < cooldown:
        return True

    recent_alerts[key] = current_time
    return False


def is_unusual_port(port: int) -> bool:
    return port not in COMMON_PORTS


def block_ip_iptables(src_ip: str) -> bool:
    if src_ip in blocked_ips:
        return False

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            text=True
        )
        blocked_ips.add(src_ip)
        logging.warning(f"[BLOCK] IP bloqueada con iptables: {src_ip}")
        return True
    except subprocess.CalledProcessError as exc:
        logging.error(
            f"[ERROR] No se pudo bloquear {src_ip} con iptables: {exc.stderr.strip()}"
        )
        return False
    except FileNotFoundError:
        logging.error("[ERROR] iptables no está instalado o no está en PATH.")
        return False


def log_detection(alert_type: str, src_ip: str, dst_port: int, action: str = "ALERT") -> None:
    logging.warning(
        f"[{action}] {alert_type} | origen={src_ip} | puerto={dst_port} | timestamp={now_str()}"
    )


def detect_syn_flood(src_ip: str, dst_port: int, do_block: bool) -> None:
    current_time = time.time()
    syn_activity[src_ip].append(current_time)
    cleanup_old_entries(syn_activity[src_ip], SYN_FLOOD_WINDOW_SECONDS, current_time)

    syn_count = len(syn_activity[src_ip])

    if syn_count >= SYN_FLOOD_THRESHOLD:
        if not should_rate_limit_alert(src_ip, "SYN_FLOOD"):
            log_detection("Posible SYN flood", src_ip, dst_port)

            if do_block:
                if block_ip_iptables(src_ip):
                    log_detection("IP bloqueada por SYN flood", src_ip, dst_port, action="BLOCK")


def detect_ack_scan(src_ip: str, dst_port: int, do_block: bool) -> None:
    current_time = time.time()
    ack_activity[src_ip].append(current_time)
    cleanup_old_entries(ack_activity[src_ip], ACK_SCAN_WINDOW_SECONDS, current_time)

    ack_ports_seen[src_ip][dst_port] = current_time
    cleanup_old_port_entries(src_ip, ACK_SCAN_WINDOW_SECONDS, current_time)

    unique_ports = len(ack_ports_seen[src_ip])
    ack_count = len(ack_activity[src_ip])

    # Regla simple: muchos ACK a varios puertos en poco tiempo
    if ack_count >= ACK_SCAN_THRESHOLD and unique_ports >= 10:
        if not should_rate_limit_alert(src_ip, "ACK_SCAN"):
            log_detection("Posible ACK scan", src_ip, dst_port)

            if do_block:
                if block_ip_iptables(src_ip):
                    log_detection("IP bloqueada por ACK scan", src_ip, dst_port, action="BLOCK")


def detect_unusual_port(src_ip: str, dst_port: int) -> None:
    if is_unusual_port(dst_port):
        if not should_rate_limit_alert(src_ip, f"UNUSUAL_PORT_{dst_port}", cooldown=30):
            log_detection("Tráfico hacia puerto inusual", src_ip, dst_port)


def packet_handler(packet, do_block: bool) -> None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    src_ip = ip_layer.src
    dst_port = int(tcp_layer.dport)
    flags = int(tcp_layer.flags)

    # Flags comunes:
    # SYN = 0x02
    # ACK = 0x10
    # SYN+ACK = 0x12

    # Detectar SYN "puro"
    if flags == 0x02:
        detect_syn_flood(src_ip, dst_port, do_block)

    # Detectar ACK "puro"
    elif flags == 0x10:
        detect_ack_scan(src_ip, dst_port, do_block)

    # Detectar puertos inusuales en cualquier TCP entrante
    detect_unusual_port(src_ip, dst_port)


def signal_handler(sig, frame) -> None:
    logging.info("Deteniendo sniffer...")
    sys.exit(0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IDS básico educativo con Scapy para detectar tráfico TCP sospechoso."
    )
    parser.add_argument(
        "--interface",
        "-i",
        default=DEFAULT_INTERFACE,
        help="Interfaz de red a monitorear, por ejemplo: eth0, ens33"
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Bloquea IPs sospechosas usando iptables"
    )
    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=SYN_FLOOD_THRESHOLD,
        help="Umbral de paquetes SYN por ventana para detectar SYN flood"
    )
    parser.add_argument(
        "--ack-threshold",
        type=int,
        default=ACK_SCAN_THRESHOLD,
        help="Umbral de paquetes ACK por ventana para detectar ACK scan"
    )
    return parser.parse_args()


def main() -> None:
    global SYN_FLOOD_THRESHOLD, ACK_SCAN_THRESHOLD

    args = parse_args()
    SYN_FLOOD_THRESHOLD = args.syn_threshold
    ACK_SCAN_THRESHOLD = args.ack_threshold

    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)

    logging.info("Iniciando sniffer_defense.py")
    logging.info(f"Interfaz: {args.interface if args.interface else 'por defecto'}")
    logging.info(f"Bloqueo automático: {'activado' if args.block else 'desactivado'}")
    logging.info("Monitoreando tráfico TCP... Presiona Ctrl+C para salir.")

    try:
        sniff(
            iface=args.interface,
            filter="tcp",
            prn=lambda pkt: packet_handler(pkt, args.block),
            store=False
        )
    except PermissionError:
        logging.error("Permisos insuficientes. Ejecuta el script como root o con sudo.")
        sys.exit(1)
    except OSError as exc:
        logging.error(f"Error al iniciar la captura: {exc}")
        sys.exit(1)
    except Exception as exc:
        logging.error(f"Error inesperado: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()