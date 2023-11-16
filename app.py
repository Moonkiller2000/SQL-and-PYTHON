from flask import Flask, render_template, request, jsonify, session, g
from argon2 import PasswordHasher
import sqlite3
import secrets

app = Flask(__name__)
ph = PasswordHasher()
NUM_ROUNDS = 16

app.secret_key = secrets.token_hex(16)

DATABASE = 'password.db'

def connect_db():
    return sqlite3.connect(DATABASE)

def get_db():
    if not hasattr(g, 'db'):
        g.db = connect_db()
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

def generate_salt():
    return secrets.token_hex(16)

def generate_hash(password, salt):
    ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8, hash_len=16, salt_len=16)
    return ph.hash(password + salt)

@app.route('/')
def index():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()

    return render_template('index.html', users=users)

@app.route('/usuarios')
def mostrar_usuarios():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        usuarios = cursor.fetchall()

    return render_template('mostrar_usuarios.html', usuarios=usuarios)

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Nombre de usuario y contraseña son requeridos'}), 400

    if len(password) < 8:
        return jsonify({'error': 'La contraseña debe tener al menos 8 caracteres'}), 400

    if user_exists(username):
        return jsonify({'error': 'Nombre de usuario ya registrado'}), 400

    salt = generate_salt()
    hashed_password = generate_hash(password, salt)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, hashed_password, salt))
        conn.commit()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Nombre de usuario y contraseña son requeridos'}), 400

    if not user_exists(username):
        return jsonify({'error': 'Credenciales inválidas'}), 401

    user_data = get_user_data(username)
    hashed_password_from_db = user_data['password_hash']
    salt = user_data['salt']

    try:
        if ph.verify(hashed_password_from_db, password + salt):
            session['username'] = username
            return jsonify({'message': 'Inicio de sesión exitoso'}), 200
        else:
            return jsonify({'error': 'Credenciales inválidas'}), 401
    except:
        return jsonify({'error': 'Credenciales inválidas'}), 401

def user_exists(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        return cursor.fetchone() is not None

def get_user_data(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        return dict(cursor.fetchone())

if __name__ == '__main__':
    app.run(debug=True)


