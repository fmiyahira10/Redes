import struct
import os
import sqlite3

# Valores iniciales de los registros hash (H)
H = [
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
    # Preprocesamiento
    mensaje = bytearray(mensaje, 'ascii')  # Convertir el mensaje a un array de bytes
    tamaño_en_bits = (8 * len(mensaje)) & 0xffffffffffffffff  # Calcular el tamaño del mensaje en bits
    mensaje.append(0x80)  # Añadir un bit '1' seguido de ceros
    while len(mensaje) % 64 != 56:  # Rellenar con ceros hasta que el tamaño sea congruente a 56 mod 64
        mensaje.append(0)
    mensaje += tamaño_en_bits.to_bytes(8, byteorder='big')  # Añadir el tamaño del mensaje al final
    
    # Procesamiento de bloques
    for bloque_inicial in range(0, len(mensaje), 64):
        bloque = mensaje[bloque_inicial:bloque_inicial + 64]  # Dividir el mensaje en bloques de 512 bits (64 bytes)
        w = list(struct.unpack('>16L', bloque)) + [0] * 48  # Desempaquetar el bloque en 16 palabras de 32 bits y extender a 64 palabras

        for i in range(16, 64):
            s0 = rotacionDerecha(w[i - 15], 7) ^ rotacionDerecha(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotacionDerecha(w[i - 2], 17) ^ rotacionDerecha(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff  # Calcular las palabras extendidas

        a, b, c, d, e, f, g, h = H  # Inicializar los valores de los registros hash

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
            a = (temp1 + temp2) & 0xffffffff  # Actualizar los valores de los registros hash

        H[0] = (H[0] + a) & 0xffffffff
        H[1] = (H[1] + b) & 0xffffffff
        H[2] = (H[2] + c) & 0xffffffff
        H[3] = (H[3] + d) & 0xffffffff
        H[4] = (H[4] + e) & 0xffffffff
        H[5] = (H[5] + f) & 0xffffffff
        H[6] = (H[6] + g) & 0xffffffff
        H[7] = (H[7] + h) & 0xffffffff  # Actualizar los valores finales de los registros hash

    # Concatenar y producir el hash final
    return ''.join(f'{value:08x}' for value in H)

def hash_con_sal(password):
    # sal de 16 bytes
    salt = os.urandom(16).hex()
    hash_salado = sha256(salt + password)
    print(f"Sal: {salt}")
    print(f"Hash salado: {hash_salado}")
    return salt, hash_salado

def verify_password(sal_almacenada, hash_almacenado, contra):
    print(f"Sal almacenada: {sal_almacenada}")
    # Combina la sal almacenada con la contraseña ingresada y calcula el hash
    hash_value = sha256(sal_almacenada + contra)
    
    # Compara el hash calculado con el hash almacenado
    return hash_value == hash_almacenado

def register_user(usuario, contra, conn):
    salt, hashed_password = hash_con_sal(contra)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, salt, hash) VALUES (?, ?, ?)", (usuario, salt, hashed_password))
    conn.commit()
    print(f"Usuario {usuario} registrado exitosamente.")


def login_user(username, password, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    if result:
        stored_salt, stored_hash = result
        print(stored_salt, stored_hash)
        hash_value = sha256(stored_salt+ password)
        print(hash_value)
        
        if verify_password(stored_salt, stored_hash, password):
            print("Inicio de sesión exitoso.")
        else:
            print("Contraseña incorrecta.")
    else:
        print("Usuario no encontrado.")

#Separado
conn = sqlite3.connect('usuarios.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL,
                    hash TEXT NOT NULL
                )''')


def main():
    register_user("Daniel", "123", conn)

    login_user("Daniel", "123", conn)
    conn.close()

main()
