from flask import Flask, render_template, request, redirect, url_for
from configs.database import Database

app = Flask(__name__)

@app.route('/<path:filename>')
def server_static(filename):
    return app.send_static_file(filename)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST']) 
def login():
    db = Database()
    username = request.form['username']
    hash = request.form['password']
    query = f"SELECT * FROM users WHERE username = '{username}' AND hash = '{hash}'"
    db.execute(query)
    return render_template('home.html')



if __name__ == '__main__':
    app.run(debug=True)