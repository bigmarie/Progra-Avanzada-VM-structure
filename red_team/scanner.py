import nmap

def main():
    scanner = nmap.PortScanner()

    target = input("Ingrese la IP o dominio a escanear: ")
    ports = input("Ingrese los puertos (ej: 22,80,443 o 1-1000): ")

    print("\n[*] Ejecutando escaneo con Nmap...\n")
    # -sV = detección de servicios
    scanner.scan(target, ports, arguments='-sV')

    for host in scanner.all_hosts():
        print(f"Host: {host}")
        print(f"Estado: {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"\nProtocolo: {proto}")

            ports_lis = scanner[host][proto].keys()
            for port in ports_lis:
                service = scanner[host][proto][port]['name']
                state = scanner[host][proto][port]['state']
                product = scanner[host][proto][port].get('product', '')
                version = scanner[host][proto][port].get('version', '')

                print(f" Puerto {port} -> {state} | Servicio: {service} {product} {version}")

if __name__ == "__main__":
    main()