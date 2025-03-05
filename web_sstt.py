# coding=utf-8
#!/usr/bin/env python3

import socket
import select
import argparse   # Leer parámetros de ejecución
import os         # Obtener ruta y extensión
import logging    # Para imprimir logs
from multiprocessing import Manager  # Para compartir estado entre procesos
import locale
import datetime

BUFSIZE = 8192              # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 20     # Timeout para la conexión persistente
MAX_ACCESOS = 10
BACKLOG = 64
AUMENTO_COOKIE_POR_DEFECTO = 1

# Extensiones admitidas (extension, MIME type)
filetypes = {
    "gif": "image/gif",
    "jpg": "image/jpg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "htm": "text/htm",
    "html": "text/html",
    "css": "text/css",
    "js": "text/js"
}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

def enviar_mensaje(cs, data):
    """Envía datos a través del socket cs."""
    return cs.send(data)

def recibir_mensaje(cs):
    """Recibe datos a través del socket cs."""
    return cs.recv(BUFSIZE)

def cerrar_conexion(cs):
    """Cierra una conexión activa."""
    cs.close()

def buscar_cabecera(cabeceras, nombre):
    """
    Busca una cabecera en la lista 'cabeceras'.
    Retorna (cabecera, True) si se encuentra o (None, False) en caso contrario.
    """
    for linea in cabeceras:
        if linea.startswith(nombre):
            return linea.strip(), True
    return None, False

# Creamos un Manager y un diccionario compartido para las cookies.
manager = Manager()
cookie_counters = manager.dict()

def process_cookies_por_ip(cs, absolute_path):
    """
    Actualiza la cookie asociada a la IP del cliente usando el diccionario compartido.
    Incrementa el contador (hasta MAX_ACCESOS) y envía la cabecera Set-Cookie.
    """
    ip, _ = cs.getpeername()

    if ip in cookie_counters:
        valor = cookie_counters[ip]
        if "index.html" in absolute_path:
            if valor < MAX_ACCESOS:
                valor += AUMENTO_COOKIE_POR_DEFECTO
            else:
                valor = MAX_ACCESOS
    else:
        valor = 1

    cookie_counters[ip] = valor

    return valor

def process_cookies(headers_str, cs):
    """
    Procesa la cookie 'cookie_counter_16YY' leyendo la petición.
    (Esta función se mantiene para cuando el cliente envía la cookie, pero
    en este ejemplo usaremos process_cookies_por_ip para persistir el valor).
    """
    header_cookie = "cookie_counter_16YY"
    cabeceras = headers_str.split("\n")
    cookie_header, found = buscar_cabecera(cabeceras, header_cookie)

    if found:
        parts = cookie_header.split(":")
        try:
            cookie_val = int(parts[1].strip())
        except (ValueError, IndexError):
            cookie_val = 1

        if cookie_val < MAX_ACCESOS:
            cookie_val += AUMENTO_COOKIE_POR_DEFECTO
        else:
            cookie_val = MAX_ACCESOS

        nueva_cabecera = f"{header_cookie}: {cookie_val}"
        for idx, cab in enumerate(cabeceras):
            if cab.startswith(header_cookie):
                cabeceras[idx] = nueva_cabecera
                break

        nueva_cadena = "\n".join(cabeceras)
        cs.send(nueva_cadena.encode())
        return cookie_val
    else:
        nueva_cabecera = f"{header_cookie}: 1"
        cabeceras.append(nueva_cabecera)
        nueva_cadena = "\n".join(cabeceras)
        cs.send(nueva_cadena.encode())
        return 1

def obtener_cabeceras(lineas):
    """
    Extrae de la lista 'lineas' (divididas por CRLF) aquellas líneas que contienen ": ".
    Se ignora la primera línea (la de solicitud).
    """
    cabeceras = []
    for linea in lineas[1:]:
        if ": " in linea:
            cabeceras.append(linea.strip())
    return cabeceras

def get_handler(cs,webroot,url):
    # Si la URL empieza por "/" se traduce a index.html
    recurso = "index.html" if url is "/" else url

    ruta_absoluta = os.path.join(webroot, recurso.lstrip("/"))

    if not os.path.isfile(ruta_absoluta):
        logger.error("404 Not found: Recurso inexistente")
        error_response = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        cs.send(error_response.encode())
        return

    # Actualizamos la cookie usando el diccionario compartido
    valor_cookie = process_cookies_por_ip(cs, ruta_absoluta)
    logger.info(f"Cookie para la IP actual: {valor_cookie}")
    if valor_cookie == MAX_ACCESOS:
        logger.error("403 Forbidden: Máximo de accesos alcanzado")
        error_response = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        cs.send(error_response.encode())
        return
    locale.setlocale(locale.LC_TIME, 'en_US.utf8')
    date = datetime.datetime.now(datetime.UTC).strftime('%a, %d %b %Y %H:%M:%S GMT')
    # Enviamos una respuesta HTTP básica con la cabecera Set-Cookie
    respuesta = (
        "HTTP/1.1 200 OK\r\n"
        "Server: web.nombreorganizacion0102.org\r\n"
        f"Set-Cookie: cookie_counter_16YY={valor_cookie}\r\n"
        "Content-Type: text/html\r\n"
        f"Content-Length: {os.path.getsize(ruta_absoluta)}\r\n"
        f"Date: {date}\r\n"
        "\r\n"
    )
    cs.send(respuesta.encode())

    with open(ruta_absoluta, "rb") as f:
        while True:
            bloque = f.read(BUFSIZE)
            logger.info(f'bloque size:{len(bloque)} and bufsize: {BUFSIZE}')
            if not bloque:
                break
            enviar_mensaje(cs, bloque)
    cerrar_conexion(cs)

def post_handler(cs,webroot,url):
    pass

def process_web_request(cs, webroot):
    """
    Procesa la petición web:
      - Espera datos (o timeout) en el socket.
      - Procesa la petición HTTP.
      - Actualiza la cookie 'cookie_counter_16YY' y la envía al cliente.
      - Verifica que el recurso exista; en caso contrario, envía error 404.
      - Envía el contenido del fichero (en modo binario).
    """

    rlist, _, _ = select.select([cs], [], [], TIMEOUT_CONNECTION)
    if cs not in rlist:
        logger.debug("Timeout sin actividad; cerrando conexión")
        return

    datos = cs.recv(BUFSIZE)
    if len(datos) <= 0:
        return

    datos_decoded = datos.decode()
    logger.info(f"Solicitud recibida:\n{datos_decoded}")
    lineas = datos_decoded.split("\r\n")
    if len(lineas) < 1:
        return

    logger.info(f"\n\ndatos:{lineas}\n\n")

    linea_solicitud = lineas[0].strip()
    partes = linea_solicitud.split(" ")
    if len(partes) != 3:
        logger.error("Línea de solicitud mal formateada")
        return

    metodo, url, version = partes

    if not version.startswith("HTTP/1.1"):
        logger.error("Versión HTTP no soportada")
        return

    metodos_validos = {"GET", "POST"}
    if metodo not in metodos_validos:
        error_response = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        cs.send(error_response.encode())
        return
    if metodo=="GET":
        get_handler(cs, webroot, url)
    else:
        post_handler(cs, webroot, url)

def main():
    """Función principal del servidor."""
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot",
                            help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)",
                            required=True)
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info(f"Enabling server in address {args.host} and port {args.port}.")
        logger.info(f"Serving files from {args.webroot}")

        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((args.host, args.port))
        servidor.listen(BACKLOG)
        logger.info("Servidor escuchando conexiones...")

        while True:
            cliente_socket, cliente_direccion = servidor.accept()
            logger.info(f"Conexión aceptada de {cliente_direccion}")
            pid = os.fork()
            if pid == 0:
                # Proceso hijo: cerrar el socket del servidor y procesar la petición
                servidor.close()
                process_web_request(cliente_socket, args.webroot)
                os._exit(0) # instead of sys.exit because sys.exit is doing the callbacks
                            # to the multiprocessing Manager, which we want to avoid
            else:
                # Proceso padre: cerrar el socket del cliente
                cliente_socket.close()
    except KeyboardInterrupt:
        logger.info("Interrupción detectada. Cerrando servidor.")
        cerrar_conexion(servidor)

if __name__ == "__main__":
    main()
