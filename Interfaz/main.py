from flask import Flask, flash, render_template, request, redirect, session, url_for
from configs.database import Database
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ScriptSQL import validar_credenciales
from proyectoRedes import cargar_clave_privada, cargar_clave_publica, login_user, register_user, verificar_sello_criptografico

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necesario para usar flash messages

path1 = os.path.join(os.path.dirname(__file__), '..' , 'public_key.pem')
path2 = os.path.join(os.path.dirname(__file__), '..' , 'private_key.pem')
private_key = cargar_clave_privada(path2)
public_key = cargar_clave_publica(path1)

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
            session['username'] = username
            session['password'] = contra
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = Database()
        db.connect()  # Conectar a la base de datos
        if not db.connection:
            flash('Error al conectar a la base de datos.', 'danger')
            return redirect(url_for('register'))
        
        username = request.form['username']
        password = request.form['password']
        
        try:
            register_user(username, password, db.connection, private_key)
            flash('Usuario registrado exitosamente.', 'success')
            return redirect(url_for('home'))
        except ValueError as e:
            flash(f'Alerta: {e}', 'danger')
            return redirect(url_for('register'))
        finally:
            db.close()  # Cerrar la conexión a la base de datos
    return render_template('register.html') 
    
@app.route('/validate_signature', methods=['POST'])
def validate_signature():
    username = session.get('username')
    password = session.get('password')
    if not username or not password:
        flash('No se encontraron credenciales de usuario.', 'danger')
        return redirect(url_for('home'))

    db = Database()
    db.connect()
    if not db.connection:
        flash('Error al conectar a la base de datos.', 'danger')
        return redirect(url_for('home'))

    cursor = db.connection.cursor()
    cursor.execute("SELECT hash, Timestamp, firma FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        hash_password, timestamp, signature = result
        signature = bytes(signature)
        if verificar_sello_criptografico(hash_password, timestamp, signature, public_key):
            flash('Firma validada correctamente.', 'success')
        else:
            flash('Error al validar la firma.', 'danger')
    else:
        flash('Usuario no encontrado.', 'danger')

    db.close()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)