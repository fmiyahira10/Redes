import os
import sqlite3
import socket
import re

Patrones = [
    r"(?:'|--|\bOR\b|\bAND\b).*?(?:--|;)",  # uso de comentarios y palabras clave
    r"(?:\bUNION\b|\bSELECT\b).*?\bFROM\b",  # intentos de UNION SELECT
    r"(?:DROP|ALTER|DELETE|INSERT).*"  # comandos peligrosos
]

conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'Interfaz', 'BaseDatos', 'usuarios.db')) ##NO CAMBIAR
conn.execute('''CREATE TABLE IF NOT EXISTS sql_injection_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    user_ip TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')

def SQLinyeccion_Deteccion(query):
    for patron in Patrones:
        if re.search(patron, query, re.IGNORECASE):
            return True
    return False

def intento_log(connection, query):
    hostname = socket.gethostname()
    ip_usuario = socket.gethostbyname(hostname)  # obtener IP local
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO sql_injection_logs (query, user_ip, status, timestamp)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    """, (query, ip_usuario, "BLOQUEADO")) ##Abierto a otras opciones
    connection.commit()

def validar_credenciales(connection, username, password):
    if SQLinyeccion_Deteccion(username) or SQLinyeccion_Deteccion(password):
        intento_log(connection, f"username: {username}, password: {password}")
        raise ValueError("Potencial SQL inyeccion detectado")
    else:
        return True

if __name__ == "__main__":
    ## ejemplo de SQL Inyect
    ## query="SELECT * FROM users WHERE username = 'admin' OR 1=1" 
    
    conn.close()