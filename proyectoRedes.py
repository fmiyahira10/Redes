import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import sqlite3
from datetime import datetime
import time
from cryptography.exceptions import InvalidSignature
from ScriptSQL import validar_credenciales

# Valores iniciales de los registros hash (H)
H_INICIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Constantes de la función SHA-256 (K)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Función para realizar una rotación a la derecha
def rotacionDerecha(n, d):
    return (n >> d | n << (32 - d)) & 0xffffffff

# Función principal para calcular el hash SHA-256
def sha256(mensaje):
    # Copia de los valores iniciales de H para cada cálculo de hash
    H = H_INICIAL[:]

    # Preprocesamiento
    mensaje = bytearray(mensaje, 'ascii')
    tamaño_en_bits = (8 * len(mensaje)) & 0xffffffffffffffff
    mensaje.append(0x80)
    while len(mensaje) % 64 != 56:
        mensaje.append(0)
    mensaje += tamaño_en_bits.to_bytes(8, byteorder='big')

    # Procesamiento de bloques
    for bloque_inicial in range(0, len(mensaje), 64):
        bloque = mensaje[bloque_inicial:bloque_inicial + 64]
        w = list(struct.unpack('>16L', bloque)) + [0] * 48

        for i in range(16, 64):
            s0 = rotacionDerecha(w[i - 15], 7) ^ rotacionDerecha(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotacionDerecha(w[i - 2], 17) ^ rotacionDerecha(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            s1 = rotacionDerecha(e, 6) ^ rotacionDerecha(e, 11) ^ rotacionDerecha(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff
            s0 = rotacionDerecha(a, 2) ^ rotacionDerecha(a, 13) ^ rotacionDerecha(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        H[0] = (H[0] + a) & 0xffffffff
        H[1] = (H[1] + b) & 0xffffffff
        H[2] = (H[2] + c) & 0xffffffff
        H[3] = (H[3] + d) & 0xffffffff
        H[4] = (H[4] + e) & 0xffffffff
        H[5] = (H[5] + f) & 0xffffffff
        H[6] = (H[6] + g) & 0xffffffff
        H[7] = (H[7] + h) & 0xffffffff

    return ''.join(f'{value:08x}' for value in H)

def hash_con_sal(password):
    # sal de 16 bytes
    salt = os.urandom(16).hex()
    hash_salado = sha256(salt + password)
    return salt, hash_salado

def generar_claves_rsa():
    privateK=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    publicK = privateK.public_key()
    return privateK, publicK

def cargar_clave_privada(path):
    with open(path, 'rb') as private_file:
        return serialization.load_pem_private_key(private_file.read(), password=None) ##Se le puede asignar clave

def cargar_clave_publica(path):
    with open(path, 'rb') as public_file:
        return serialization.load_pem_public_key(public_file.read())
    
def saveK(privateK, publicK): ## Guarda las claves en archivos
    ROOT_DIR = os.path.dirname(__file__)
    PRIVATE_KEY_PATH = os.path.join(ROOT_DIR, 'private_key.pem')
    PUBLIC_KEY_PATH = os.path.join(ROOT_DIR, 'public_key.pem')

    with open(PRIVATE_KEY_PATH, 'wb') as private_file:
        private_file.write(privateK.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(PUBLIC_KEY_PATH, 'wb') as public_file:
        public_file.write(publicK.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def cifrar_datos(public_key,data): ##Cifra los datos con la clave publica en bytes
    return public_key.encrypt(data.encode('utf-8'),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

def descifrar_datos(private_key, encrypted_data): ##Descifra los datos con la clave privada de bytes a texto
    return private_key.decrypt(encrypted_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None)).decode('utf-8')

def verify_password(sal_almacenada, hash_almacenado, contra):
    hash_value = sha256(sal_almacenada + contra)
    return hash_value == hash_almacenado

def register_user(usuario, contra, conn):
    salt, hashed_salado = hash_con_sal(contra)
    path = os.path.join(os.path.dirname(__file__), 'private_key.pem')
    timestamp, signature = generar_sello_criptografico(hashed_salado, cargar_clave_privada(path))
    try:
        with conn:
            conn.execute("INSERT INTO users (username, salt, hash, Timestamp, firma) VALUES (?, ?, ?, ?, ?)", (usuario, salt, hashed_salado, timestamp, sqlite3.Binary(signature)))
        print(f"Usuario {usuario} registrado exitosamente.")
    except sqlite3.IntegrityError:
        print(f"El usuario ya existe.")
    except Exception as e:
        print(f"Error al registrar usuario: {e}")

def login_user(username, password, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    if result:
        stored_salt, stored_hash = result
        if verify_password(stored_salt, stored_hash, password):
            print("Inicio de sesión exitoso.")
            return 1
        else:
            print("Contraseña incorrecta.")
            return 2
    else:
        print("Usuario no encontrado.")
        return 3

def generar_sello_criptografico(hash_password, private_key):
    timestamp = str(int(time.time()))  # Epoch time
    data = f"{hash_password}|{timestamp}"

    # Firmar el dato
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return timestamp, signature

def verificar_sello_criptografico(hash_password, timestamp, signature, public_key):
    data = f"{hash_password}|{timestamp}"
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Integridad validada: el hash no ha sido alterado.")
        return True
    except InvalidSignature:
        print("Error: el hash ha sido modificado o el sello no es válido.")
        return False

# Separado
conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'Interfaz', 'BaseDatos', 'usuarios.db')) ##NO CAMBIAR
conn.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    Timestamp TIMESTAMP,
                    firma BLOB NOT NULL
                )''')


def main():
    
    ROOT_DIR = os.path.dirname(__file__)
    PRIVATE_KEY_PATH = os.path.join(ROOT_DIR, 'private_key.pem')
    PUBLIC_KEY_PATH = os.path.join(ROOT_DIR, 'public_key.pem')

    # Verificar si las claves existen (unificado para main.py)
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        print("Claves no encontradas, generando nuevas...")
        private_key, public_key = generar_claves_rsa()
        saveK(private_key, public_key)
        print(f"Claves generadas y guardadas en:\n{PRIVATE_KEY_PATH}\n{PUBLIC_KEY_PATH}")
    else:
        print("Claves existentes encontradas. Cargando...")
        private_key = cargar_clave_privada(PRIVATE_KEY_PATH)
        public_key = cargar_clave_publica(PUBLIC_KEY_PATH)
        print("Claves cargadas correctamente.")

    register_user("Daniel", "password", conn)
    register_user("Admin", "soyadmin", conn)

    hash_mensaje=sha256("123")
    print(hash_mensaje)
    hash_encriptado=cifrar_datos(public_key,hash_mensaje)

    print(f"Hash cifrado: {hash_encriptado}")
    print(f"Hash original: {descifrar_datos(private_key,hash_encriptado)}")

    conn.close()
main()
