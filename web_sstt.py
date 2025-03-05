# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors    #https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs



BUFSIZE = 8192 # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 20 # Timout para la conexión persistente
MAX_ACCESOS = 10
BACKLOG = 64 
AUMENTO_COOKIE_POR_DEFECTO = 1

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    return cs.send(data)



def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    return cs.recv(BUFSIZE)


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()
    return


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """

    header_cookie = "cookie_counter_16YY"
    #headers = headers.decode()
    cabeceras = headers.split('\n')
    cookie_header, found = buscar_cabecera(cabeceras, header_cookie)
    """
    headers = headers.decode()
    cabeceras = headers.split('\n')
    for i in cabeceras:
        print(i)
        if i.startswith('Cookie'):   
            if i.split(':')[1] == MAX_ACCESOS:
                found = True
                return MAX_ACCESOS
            else:
                i='Cookie: '+ i.split(":")[1] + 1
                found = True
                cadena = ' '.join(cabeceras)
                cadena = cadena.encode()
                cs.send(cadena)
                cookie_valor = i.split(":")[1]
                cookie_int = int(cookie_valor)
                cookie_int=+ AUMENTO_COOKIE_POR_DEFECTO
                i.split(":")[1] = cookie_int
                found = True
                cadena = ' '.join(cabeceras)
                cadena = cadena.encode()
                cs.send(cadena)
                return cookie_int
    if not found:
        cabeceras.append('Cookie: 1\n')
        cadena = ' '.join(cabeceras)
        cadena = cadena.encode()
        cs.send(cadena)
        return 1"""
    if found:
        # Se espera que el formato sea "cookie_counter_16YY: <valor>"
        parts = cookie_header.split(":")
        if len(parts) < 2:
            # Si el formato es incorrecto, se establece el contador en 1
            cookie_val = 1
        else:
            try:
                cookie_val = int(parts[1].strip())
            except ValueError:
                cookie_val = 1

        if cookie_val >= MAX_ACCESOS:
            print("Maximo valor cookie")
            cookie_val = MAX_ACCESOS
        else:
            cookie_val += AUMENTO_COOKIE_POR_DEFECTO
            print(f"Valor de la cookie actual: {cookie_val}")

        # Actualizar la cabecera en la lista
        nueva_cabecera = f"{header_cookie}: {cookie_val}"
        for idx, cab in enumerate(cabeceras):
            if cab.startswith(header_cookie):
                cabeceras[idx] = nueva_cabecera
                break

        # Reconstruir la cadena de cabeceras y enviarla
        nueva_cadena = "\n".join(cabeceras)
        cs.send(nueva_cadena.encode())
        print("Enviar cabecera")
        return cookie_val
    else:
        # Si no se encontró la cabecera, se añade con valor 1
        nueva_cabecera = f"{header_cookie}: 1"
        cabeceras.append(nueva_cabecera)
        nueva_cadena = "\n".join(cabeceras)
        cs.send(nueva_cadena.encode())
        print("Crear cabecera")
        return 1


def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()"""
    while True:

        """ * Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
              sin recibir ningún mensaje o hay datos. Se utiliza select.select """
        rsublist, _, _ = select.select([cs],[],[],TIMEOUT_CONNECTION)
        ## * Si no es por timeout y hay datos en el socket cs
        if cs in rsublist:
         ##       * Leer los datos con recv.
            datos = cs.recv(BUFSIZE)
            if len(datos) <= 0:
                break
            datos = datos.decode()
            logger.info(datos)
         ##       * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
         # EJEMPLO: GET /index.html HTTP/1.1\r\n
            lineas = datos.split("\r\n")
            linea_solicitud = lineas[0].strip(" ")
            partes = linea_solicitud.split(" ")

            if len(partes) != 3:
                break
            metodo, url, version = partes
        ##          * Devuelve una lista con los atributos de las cabeceras.
            cabeceras = obtener_cabeceras(lineas)
         ##           * Comprobar si la versión de HTTP es 1.1
            if not version.startswith("HTTP/1.1"):
                break
        ##           * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
            metodos_validos = {"GET", "POST"}
            if metodo not in metodos_validos:
                logger.error("405 Method Not Allowed: Invalid HTTP method") # DUDA
                break
         ##           * Leer URL y eliminar parámetros si los hubiera
            recurso= url # FALTA HACERLO
         ##           * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
            if  recurso.startswith("/"):
                recurso = "index.html"
         ##           * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
            ruta_absoluta = os.path.join(webroot, recurso.lstrip("/"))
         ##          * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
            if os.path.isfile(ruta_absoluta):
                logger.error("404 Not found")
         ##           * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
            for c in cabeceras:
                print("c")
                if c.startswith('cookie_counter_16YY:'):
                    cookie_header = c
                    #found = True
                    valor_cookie = process_cookies(datos,cs)
         ##             el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
         ##             Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    if valor_cookie == MAX_ACCESOS:
                        logger.error("403 Forbidden") 
         ##           * Obtener el tamaño del recurso en bytes.
            tamano_recurso = os.stat(ruta_absoluta).st_size
         ##           * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
            _, extension = os.path.splitext(ruta_absoluta)
            extension = extension.lstrip(".")
         ##           * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y      
         ##             las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
         ##             Content-Length y Content-Type.
            
            #cabecera_Date = buscar_cabecera('Date :')
            #cabecera_Server = buscar_cabecera('Server :')
            #cabecera_Connection = buscar_cabecera('Connection :')
            #cabecera_Set_Cookie = buscar_cabecera('Set-Cookie :')
            #cabecera_Content_Length = buscar_cabecera('Content-Length :')
            #cabecera_Content_Type = buscar_cabecera( 'Content-Type :')
         
         ##           * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
           ##           * Se abre el fichero en modo lectura y modo binario
            with open(ruta_absoluta, "rb") as f:  
                while True:
            
                    ##              * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                    bloque = f.read(BUFSIZE)
                    ##                * Cuando ya no hay más información para leer, se corta el bucle 
                    if not bloque:  
                        break  
                    enviar_mensaje(cs, bloque)  
        """    * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
        """
def obtener_cabeceras(datos):
    cabeceras = []
    for linea in datos[1:]:
        if ": " in linea: 
            cabeceras.append(linea.strip())  
            ##nombre, valor = linea.split(": ", 1)
            ##cabeceras.append((nombre.strip(), valor.strip()))   
    return cabeceras

    
def buscar_cabecera(cabeceras, c):
    for linea in cabeceras:
        if linea.startswith(c):
            return linea.strip(), True
    return None, False


def main():
    """ Función principal del servidor
    """

    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()


        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))


    ## Funcionalidad a realizar
        ##   * Crea un socket TCP (SOCK_STREAM) 
        servidor = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)
        ##  * Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        ##  * Vinculamos el socket a una IP y puerto elegidos
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((args.host, args.port))
        ## * Escucha conexiones entrantes
        servidor.listen(BACKLOG)
        ## * Bucle infinito para mantener el servidor activo indefinidamente
        while True:
            ## - Aceptamos la conexión
            cliente_socket, cliente_direccion = servidor.accept()
            ## - Creamos un proceso hijo
            pid = os.fork()

            ## - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()
            if pid == 0:  
                servidor.close()
                process_web_request(cliente_socket, args.webroot) 
                ## values = recibir_mensaje(cliente_socket)          
                ##process_cookies(values, cliente_socket)
                
            ## - Si es el proceso padre cerrar el socket que gestiona el hijo.
            else:
                cliente_socket.close()
    except KeyboardInterrupt:
        cerrar_conexion(servidor)

if __name__== "__main__":
    main()
