from flask import Flask, flash, render_template, request, redirect, url_for
from configs.database import Database
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ScriptSQL import validar_credenciales
from proyectoRedes import cargar_clave_privada, cargar_clave_publica, login_user

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
    db.connect()  # Conectar a la base de datos
    if not db.connection:
        flash('Error al conectar a la base de datos.', 'danger')
        return redirect(url_for('home'))
    
    username = request.form['username']
    contra = request.form['password']
    
    try:
        validar_credenciales(db.connection, username, contra)

        if (login_user(username, contra, db.connection)==1):
            flash('Inicio de sesión exitoso.', 'success')
            return render_template('home.html')
        
        elif(login_user(username, contra, db.connection)==2):
            flash('Contraseña incorrecta', 'danger')
            return redirect(url_for('home'))

        else:
            flash('Usuario no encontrado.', 'danger')
            return redirect(url_for('home'))
    except ValueError as e:
        flash(f'Alerta: {e}', 'danger')
        return redirect(url_for('home'))
    
if __name__ == '__main__':
    app.run(debug=True)