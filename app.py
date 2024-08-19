from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from base64 import b64encode, b64decode
import hashlib
import mysql.connector
import os
from db import get_db_connection
from flask import session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Fixed Triple DES key (24 bytes long)
fixed_key_des3 = b'123456789012345678901234'  # 24-byte key for 3DES

# Pre-generated RSA keys (for demonstration purposes)
private_key_rsa = RSA.generate(2048)
public_key_rsa = private_key_rsa.publickey()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (username, hashed_password, role))
        connection.commit()
        cursor.close()
        connection.close()

        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, hashed_password))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user:
            session['username'] = username
            session['role'] = user[3]
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html')
    return redirect(url_for('login'))


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        message = request.form['message']
        role = request.form['role']

        # RSA Encryption using predefined public key
        cipher_rsa = PKCS1_OAEP.new(public_key_rsa)
        encrypted_message_rsa = cipher_rsa.encrypt(message.encode())

        # Triple DES Encryption using the fixed key and ECB mode
        cipher_des3 = DES3.new(fixed_key_des3, DES3.MODE_ECB)
        encrypted_message_des3 = cipher_des3.encrypt(encrypted_message_rsa)

        # Save encrypted message to DB
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            'INSERT INTO messages (message, role) VALUES (%s, %s)',
            (b64encode(encrypted_message_des3).decode('utf-8'), role)
        )
        connection.commit()
        cursor.close()
        connection.close()

        flash('Message encrypted and saved successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('encrypt.html')


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if 'role' not in session:
        # Redirect to login or handle missing session case
        return redirect(url_for('login'))

    if request.method == 'POST':
        connection = get_db_connection()
        if connection is None:
            return 'Failed to connect to the database.'

        cursor = connection.cursor()

        try:
            role = session['role']  # Fetch the role from the session
            cursor.execute('SELECT message FROM messages WHERE role = %s', (role,))
            results = cursor.fetchall()

            messages = []
            if results:
                for result in results:
                    encrypted_message_des3 = b64decode(result[0])

                    # Triple DES Decryption using the fixed key and ECB mode
                    cipher_des3 = DES3.new(fixed_key_des3, DES3.MODE_ECB)
                    decrypted_message_rsa = cipher_des3.decrypt(encrypted_message_des3)

                    # RSA Decryption using predefined private key
                    cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
                    decrypted_message = cipher_rsa.decrypt(decrypted_message_rsa).decode()

                    messages.append(decrypted_message)

            return render_template('decrypt.html', messages=messages)

        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            return 'An error occurred while accessing the database.'

        finally:
            cursor.close()
            connection.close()

    return render_template('decrypt.html', messages=[])




@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
