import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), '..', 'BaseDatos', 'usuarios.db')

class Database:
    def __init__(self):
        ##self.db_name = 'Interfaz/BaseDatos/usuarios.db'
        self.connection = None

    def connect(self):
        """Establecer una conexión a la base de datos."""
        try:
            self.connection = sqlite3.connect(db_path)
            print("Conexión a la base de datos establecida.")
        except sqlite3.Error as e:
            print(f"Error al conectar a la base de datos: {e}")
            self.connection = None

    def close(self):
        """Cerrar la conexión a la base de datos."""
        if self.connection:
            self.connection.close()
            self.connection = None
            print("Conexión cerrada.")

    def execute(self, query, params=()):
        """Ejecutar una consulta SQL."""
        self.connect()  # Asegúrate de estar conectado
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        self.connection.commit()
        return cursor

    def fetchall(self, query, params=()):
        """Ejecutar una consulta SQL y devolver todos los resultados."""
        cursor = self.execute(query, params)
        return cursor.fetchall()

    def fetchone(self, query, params=()):
        """Ejecutar una consulta SQL y devolver un único resultado."""
        cursor = self.execute(query, params)
        return cursor.fetchone()

    

