from scapy.all import IP, ICMP, UDP, TCP, Raw, send
import random
import time

def pedir_ip_config():
    print("\n=== Configuración de cabecera IP ===")
    src_ip = input("IP origen (dejar vacío para automática): ").strip()
    dst_ip = input("IP destino: ").strip()
    
    ttl_input = input("TTL (default 64): ").strip()
    ip_id_input = input("ID del paquete IP (default aleatorio): ").strip()

    ttl = int(ttl_input) if ttl_input else 64
    ip_id = int(ip_id_input) if ip_id_input else random.randint(1, 65535)

    return src_ip, dst_ip, ttl, ip_id


def pedir_payload():
    print("\n=== Configuración de payload ===")
    payload = input("Ingrese el payload (dejar vacío si no desea contenido): ")
    return payload


def pedir_cantidad():
    cantidad_input = input("Cantidad de paquetes a enviar: ").strip()
    return int(cantidad_input) if cantidad_input else 1


def construir_ip(src_ip, dst_ip, ttl, ip_id):
    if src_ip:
        return IP(src=src_ip, dst=dst_ip, ttl=ttl, id=ip_id)
    else:
        return IP(dst=dst_ip, ttl=ttl, id=ip_id)


def enviar_icmp():
    print("\n***** TRÁFICO ICMP *****")
    src_ip, dst_ip, ttl, ip_id = pedir_ip_config()
    payload = pedir_payload()
    cantidad = pedir_cantidad()

    for i in range(cantidad):
        paquete = construir_ip(src_ip, dst_ip, ttl, ip_id) / ICMP()

        if payload:
            paquete = paquete / Raw(load=payload)

        print(f"\nPaquete ICMP #{i+1}")
        paquete.show()
        send(paquete, verbose=False)
        print("Enviado correctamente.")
        time.sleep(1)


def enviar_udp():
    print("\n***** TRÁFICO UDP *****")
    src_ip, dst_ip, ttl, ip_id = pedir_ip_config()

    sport_input = input("Puerto origen UDP (vacío = aleatorio): ").strip()
    dport_input = input("Puerto destino UDP: ").strip()

    payload = pedir_payload()
    cantidad = pedir_cantidad()

    sport = int(sport_input) if sport_input else random.randint(1024, 65535)
    dport = int(dport_input)

    for i in range(cantidad):
        paquete = construir_ip(src_ip, dst_ip, ttl, ip_id) / UDP(sport=sport, dport=dport)

        if payload:
            paquete = paquete / Raw(load=payload)

        print(f"\nPaquete UDP #{i+1}")
        paquete.show()
        send(paquete, verbose=False)
        print("Enviado correctamente.")
        time.sleep(1)


def enviar_tcp():
    print("\n***** TRÁFICO TCP *****")
    src_ip, dst_ip, ttl, ip_id = pedir_ip_config()

    sport_input = input("Puerto origen TCP (vacío = aleatorio): ").strip()
    dport_input = input("Puerto destino TCP: ").strip()
    flags = input("Flags TCP (ejemplo: S, SA, A, F, R, PA): ").strip().upper()
    seq_input = input("Número de secuencia (vacío = aleatorio): ").strip()

    payload = pedir_payload()
    cantidad = pedir_cantidad()

    sport = int(sport_input) if sport_input else random.randint(1024, 65535)
    dport = int(dport_input)
    seq = int(seq_input) if seq_input else random.randint(1000, 99999)

    for i in range(cantidad):
        paquete = construir_ip(src_ip, dst_ip, ttl, ip_id) / TCP(
            sport=sport,
            dport=dport,
            flags=flags,
            seq=seq
        )

        if payload:
            paquete = paquete / Raw(load=payload)

        print(f"\nPaquete TCP #{i+1}")
        paquete.show()
        send(paquete, verbose=False)
        print("Enviado correctamente.")
        time.sleep(1)


def menu():
    while True:
        print("\n=========== MENÚ ===========")
        print("1. Enviar tráfico ICMP")
        print("2. Enviar tráfico UDP")
        print("3. Enviar tráfico TCP")
        print("4. Salir")

        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            enviar_icmp()
        elif opcion == "2":
            enviar_udp()
        elif opcion == "3":
            enviar_tcp()
        elif opcion == "4":
            print("Saliendo del programa...")
            break
        else:
            print("Opción inválida. Intente de nuevo.")


if __name__ == "__main__":
    menu()
