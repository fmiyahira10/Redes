import sqlite3
import re

Patrones=[
    r"(?:'|--|\bOR\b|\bAND\b).*?(?:--|;)", #uso de comentarios y palabras clave
    r"(?:\bUNION\b|\bSELECT\b).*?\bFROM\b", #intentos de UNION SELECT
    r"(?:DROP|ALTER|DELETE|INSERT).*" #comandos peligroso
]


def SQLinyeccion_Deteccion(query):
    for patron in Patrones:
        if re.search(patron, query,re.IGNORECASE):
            return True
    return False


def intento_log(connection, query, ip_usuario, estado):
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO sql_injection_logs (query, user_ip, status)
        VALUES (?, ?, ?)
    """, (query,ip_usuario,estado))
    connection.commit()

def query_procesado(connection, query, ip_usuario):
    if SQLinyeccion_Deteccion(query):
        intento_log(connection,query,ip_usuario,"Bloqueado")
        raise ValueError("Potencial SQL inyeccion detectado")
    else:
        cursor=connection.cursor()
        cursor.execute(query)
        connection.commit()

if __name__=="__main__":
    conn=sqlite3.connect("usuarios.db")
    query="SELECT * FROM users WHERE username = 'admin' OR 1=1"
    ip_usuario="192.168.1.1"

    try:
        query_procesado(conn, query, ip_usuario)
    except ValueError as e:
        print("Alerta: ", e)
    conn.close