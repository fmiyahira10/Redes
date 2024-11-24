from flask import Flask, flash, render_template, request, redirect, url_for
from configs.database import Database
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ScriptSQL import validar_credenciales
from proyectoRedes import sha256, hash_con_sal, cargar_clave_privada, cargar_clave_publica

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necesario para usar flash messages

# Cargar las claves
private_key = cargar_clave_privada()
public_key = cargar_clave_publica()

@app.route('/<path:filename>')
def server_static(filename):
    return app.send_static_file(filename)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST']) 
def login():
    db = Database()
    db.connect()
    username = request.form['username']
    contra = request.form['password']
    hash_salado = hash_con_sal(contra)
    
    cursor = db.connection.cursor()
    cursor.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone() 
    try:
        if result:
            stored_salt, stored_hash = result
            if validar_credenciales(stored_salt, stored_hash, hash_salado):
                flash('Inicio de sesión exitoso.', 'success')
                return render_template('home.html')
            else:
                flash('Credenciales inválidas.', 'danger')
                return redirect(url_for('home'))
        else:
            print("Usuario no encontrado.")
    except ValueError as e:
        flash(f'Alerta: {e}', 'danger')
        return redirect(url_for('home'))
    finally:
        db.close()  # Cerrar la conexión a la base de datos

if __name__ == '__main__':
    app.run(debug=True)