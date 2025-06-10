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

from urllib.parse import unquote

# Suma para calcular timeout de persistencia (1+9+1+2+10 = 23 s)
suma = 1 + 9 + 1 + 2 + 10

BUFSIZE = 8192              # Tamaño máximo del buffer
TIMEOUT_CONNECTION = suma   # Timeout para la conexión persistente (23 segundos)
MAX_ACCESOS = 10
BACKLOG = 64
AUMENTO_COOKIE_POR_DEFECTO = 1

# Nombre del servidor para cabecera uniforme
SERVER_NAME = 'web.internetmagico1219.org'

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

# Funciones auxiliares:

def enviar_mensaje(cs, data):
    return cs.send(data)

def recibir_mensaje(cs):
    return cs.recv(BUFSIZE)

def cerrar_conexion(cs):
    cs.close()

def buscar_cabecera(cabeceras, nombre):
    for linea in cabeceras:
        if linea.startswith(nombre):
            return linea.strip(), True
    return None, False

# Manager y diccionario compartido para cookies
manager = Manager()
cookie_counters = manager.dict()

def process_cookies_por_ip(cs, absolute_path):
    ip, _ = cs.getpeername()
    valor = cookie_counters.get(ip, 0)
    if os.path.basename(absolute_path) == 'index.html':
        if valor < MAX_ACCESOS:
            valor += AUMENTO_COOKIE_POR_DEFECTO
        else:
            valor = MAX_ACCESOS
    cookie_counters[ip] = valor
    return valor

locale.setlocale(locale.LC_TIME, 'en_US.utf8')

# Manejadores de GET y POST

def get_handler(cs, webroot, url):
    recurso = 'index.html' if url == '/' else url
    ruta_absoluta = os.path.join(webroot, recurso.lstrip('/'))

    # 404 Not Found
    if not os.path.isfile(ruta_absoluta):
        logger.error('404 Not Found: %s no existe', recurso)
        error_headers = [
            'HTTP/1.1 404 Not Found',
            f'Server: {SERVER_NAME}',
            'Content-Type: text/html',
            'Content-Length: 0',
            'Connection: close',
            '', ''
        ]
        try:
            logger.error('\r\n'.join(error_headers))
            cs.send('\r\n'.join(error_headers).encode())
        except BrokenPipeError:
            logger.warning('Cliente cerró la conexión antes de recibir el 404')
        finally:
            cerrar_conexion(cs)
        return

    # 200 OK
    date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers = [
        'HTTP/1.1 200 OK',
        f'Server: {SERVER_NAME}',
        f'Connection: keep-alive',
        f'Keep-Alive: timeout={TIMEOUT_CONNECTION}'
    ]

    # Cookies en index.html
    if recurso == 'index.html':
        valor_cookie = process_cookies_por_ip(cs, ruta_absoluta)
        logger.info('Cookie para index.html: %d', valor_cookie)
        if valor_cookie == MAX_ACCESOS:
            # 403 Forbidden
            logger.error('403 Forbidden: Máximo de accesos alcanzado')
            error_headers = [
                'HTTP/1.1 403 Forbidden',
                f'Server: {SERVER_NAME}',
                'Content-Type: text/html',
                'Content-Length: 0',
                'Connection: close',
                '', ''
            ]
            try:
                logger.error('\r\n'.join(error_headers))
                cs.send('\r\n'.join(error_headers).encode())
            except BrokenPipeError:
                logger.warning('Cliente cerró la conexión antes de recibir el 403')
            finally:
                cerrar_conexion(cs)
            return
        headers.append(f'Set-Cookie: cookie_counter_1219={valor_cookie}; Max-Age=120; Path=/')

    # Tipo MIME, longitud y fecha
    ext = os.path.splitext(ruta_absoluta)[1].lstrip('.').lower()
    mime = filetypes.get(ext, 'application/octet-stream')
    headers.extend([
        f'Content-Type: {mime}',
        f'Content-Length: {os.path.getsize(ruta_absoluta)}',
        f'Date: {date}',
        '', ''
    ])

    # Enviar respuesta
    try:
        logger.info('\r\n'.join(headers))
        cs.send('\r\n'.join(headers).encode())
    except BrokenPipeError:
        logger.warning('Cliente cerró la conexión antes de recibir las cabeceras')
        cerrar_conexion(cs)
        return

    with open(ruta_absoluta, 'rb') as f:
        while True:
            bloque = f.read(BUFSIZE)
            if not bloque:
                break
            try:
                cs.send(bloque)
            except BrokenPipeError:
                logger.warning('Cliente cerró la conexión leyendo el body')
                break

    cerrar_conexion(cs)


def post_handler(cs, webroot, url, form_data):
    recurso = 'accion_form.html' if url == '/' else url
    ruta_absoluta = os.path.join(webroot, recurso.lstrip('/'))

    # 404 Not Found POST
    if not os.path.isfile(ruta_absoluta):
        logger.error('404 Not Found: %s', ruta_absoluta)
        error_headers = [
            'HTTP/1.1 404 Not Found',
            f'Server: {SERVER_NAME}',
            'Content-Type: text/html',
            'Content-Length: 0',
            'Connection: close',
            '', ''
        ]
        try:
            logger.error('\r\n'.join(error_headers))
            cs.send('\r\n'.join(error_headers).encode())
        except BrokenPipeError:
            pass
        finally:
            cerrar_conexion(cs)
        return

    # Procesar formulario
    if form_data.startswith('email='):
        email = unquote(form_data.split('=', 1)[1])
        date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        valor_cookie = process_cookies_por_ip(cs, ruta_absoluta)
        status_line = 'HTTP/1.1 200 OK'
        body_file = 'correo_correcto.html' if email.endswith('@um.es') else 'correo_incorrecto.html'
        ruta_absoluta = os.path.join(webroot, body_file)

        if not os.path.isfile(ruta_absoluta):
            logger.error('404 Not Found: %s', ruta_absoluta)
            error_headers = [
                'HTTP/1.1 404 Not Found',
                f'Server: {SERVER_NAME}',
                'Content-Type: text/html',
                'Content-Length: 0',
                'Connection: close',
                '', ''
            ]
            try:
                logger.error('\r\n'.join(error_headers))
                cs.send('\r\n'.join(error_headers).encode())
            except BrokenPipeError:
                pass
            finally:
                cerrar_conexion(cs)
            return

        # Cabeceras respuesta POST
        headers = [
            status_line,
            'Connection: keep-alive',
            f'Keep-Alive: timeout={TIMEOUT_CONNECTION}',
            f'Server: {SERVER_NAME}',
            f'Set-Cookie: cookie_counter_1619={valor_cookie}; Max-Age=120; Path=/',
            'Content-Type: text/html',
            f'Content-Length: {os.path.getsize(ruta_absoluta)}',
            f'Date: {date}',
            '', ''
        ]
        try:
            logger.error('\r\n'.join(headers))
            cs.send('\r\n'.join(headers).encode())
        except BrokenPipeError:
            cerrar_conexion(cs)
            return

        with open(ruta_absoluta, 'rb') as f:
            while True:
                bloque = f.read(BUFSIZE)
                if not bloque:
                    break
                try:
                    cs.send(bloque)
                except BrokenPipeError:
                    break

    cerrar_conexion(cs)


def process_web_request(cs, webroot):
    # Esperar petición o timeout
    rlist, _, _ = select.select([cs], [], [], TIMEOUT_CONNECTION)
    if cs in rlist:
        datos = cs.recv(BUFSIZE)
        if not datos:
            cerrar_conexion(cs)
            return
    else:
        cerrar_conexion(cs)

    # Separar cabeceras (raw header) y resto (body parcial)
    try:
        raw_header, rest = datos.split(b'\r\n\r\n', 1)
    except ValueError:
        raw_header = datos
        rest = b''

    datos_decoded = raw_header.decode(errors='replace')
    lineas = datos_decoded.split('\r\n')
    if not lineas:
        cerrar_conexion(cs)
        return

    linea_solicitud = lineas[0].strip()
    partes = linea_solicitud.split(' ')

    # Bad Request
    if len(partes) != 3:
        logger.error('400 Bad Request: formato de petición incorrecto')
        error_headers = [
            'HTTP/1.1 400 Bad Request',
            f'Server: {SERVER_NAME}',
            'Content-Type: text/html',
            'Content-Length: 0',
            'Connection: close',
            '', ''
        ]
        try:
            logger.error('\r\n'.join(error_headers))
            cs.send('\r\n'.join(error_headers).encode())
        except BrokenPipeError:
            pass
        finally:
            cerrar_conexion(cs)
        return

    metodo, url, version = partes

    # HTTP Version
    if version not in ('HTTP/1.1', 'HTTP/1.0'):
        logger.error('505 HTTP Version Not Supported: %s', version)
        error_headers = [
            'HTTP/1.1 505 HTTP Version Not Supported',
            f'Server: {SERVER_NAME}',
            'Content-Type: text/html',
            'Content-Length: 0',
            'Connection: close',
            '', ''
        ]
        try:
            logger.error('\r\n'.join(error_headers))
            cs.send('\r\n'.join(error_headers).encode())
        except BrokenPipeError:
            pass
        finally:
            cerrar_conexion(cs)
        return

    # Métodos soportados
    if metodo not in ('GET', 'POST'):
        logger.error('405 Method Not Allowed: %s', metodo)
        error_headers = [
            'HTTP/1.1 405 Method Not Allowed',
            f'Server: {SERVER_NAME}',
            'Allow: GET, POST',
            'Content-Type: text/html',
            'Content-Length: 0',
            'Connection: close',
            '', ''
        ]
        try:
            logger.error('\r\n'.join(error_headers))
            cs.send('\r\n'.join(error_headers).encode())
        except BrokenPipeError:
            pass
        finally:
            cerrar_conexion(cs)
        return

    # Delegar a GET o POST
    if metodo == 'GET':
        get_handler(cs, webroot, url)
    else:
        # Leer body según Content-Length, usando lo que ya vino en 'rest'
        content_length, found = buscar_cabecera(lineas, 'Content-Length:')
        form_data = ''
        if found:
            try:
                length = int(content_length.split(':', 1)[1].strip())
                body_bytes = rest
                remaining = length - len(body_bytes)
                while remaining > 0:
                    chunk = cs.recv(min(remaining, BUFSIZE))
                    if not chunk:
                        break
                    body_bytes += chunk
                    remaining -= len(chunk)
                form_data = body_bytes.decode(errors='replace')
            except Exception:
                logger.warning('Error leyendo cuerpo de la petición')
        post_handler(cs, webroot, url, form_data)


def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-p', '--port', type=int, required=True)
        parser.add_argument('-ip', '--host', required=True)
        parser.add_argument('-wb', '--webroot', required=True)
        parser.add_argument('-v', '--verbose', action='store_true')
        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Servidor en %s:%d, sirviendo %s', args.host, args.port, args.webroot)
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((args.host, args.port))
        servidor.listen(BACKLOG)

        while True:
            cs, addr = servidor.accept()
            logger.info('Conexión desde %s', addr)
            pid = os.fork()
            if pid == 0:
                servidor.close()
                process_web_request(cs, args.webroot)
                os._exit(0)
            else:
                cs.close()
    except KeyboardInterrupt:
        logger.info('Interrupción detectada. Cerrando servidor.')
    finally:
        servidor.close()

if __name__ == "__main__":
    main()
