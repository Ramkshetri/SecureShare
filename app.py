from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import uuid
from utils.crypto import encrypt_file, unpad
from Crypto.Cipher import AES as AES_Cipher

app = Flask(__name__)
app.secret_key = 'securesecret123'  # Needed for session and flash messages

# File upload config
UPLOAD_FOLDER = 'static/uploads/'
ENCRYPTION_KEY = b'0123456789abcdef0123456789abcdef'  # AES-256 key
# SQLite connection function
def get_db_connection():
    conn = sqlite3.connect('db.sqlite3')
    conn.row_factory = sqlite3.Row
    return conn

# Home Page
# Home Page with file listing
@app.route('/')
def home():
    files = []
    if 'username' in session:
        conn = get_db_connection()
        files = conn.execute(
            'SELECT original_filename, stored_filename FROM files WHERE user = ?',
            (session['username'],)
        ).fetchall()
        conn.close()
    return render_template('home.html', files=files)

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

# Upload File + Encrypt
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('Login to upload files.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)

        original_filename = file.filename
        file_id = str(uuid.uuid4())
        temp_path = os.path.join(UPLOAD_FOLDER, file_id + "_temp")
        enc_path = os.path.join(UPLOAD_FOLDER, file_id + ".enc")

        file.save(temp_path)
        encrypt_file(temp_path, enc_path, ENCRYPTION_KEY)
        os.remove(temp_path)

        # Save to DB
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO files (user, original_filename, stored_filename) VALUES (?, ?, ?)',
            (session['username'], original_filename, file_id + ".enc")
        )
        conn.commit()
        conn.close()

        flash(Markup(f'File uploaded and encrypted! <a href="/download/{file_id}" class="alert-link">Download Now</a>'), 'success')
        return redirect(url_for('home'))

    return render_template('upload.html')


# ✅ Separate DELETE Route
@app.route('/delete', methods=['POST'])
def delete_file():
    if 'username' not in session:
        flash('Please log in to delete files.', 'warning')
        return redirect(url_for('login'))

    stored_filename = request.form['stored_filename']
    conn = get_db_connection()
    conn.execute('DELETE FROM files WHERE stored_filename = ? AND user = ?', (stored_filename, session['username']))
    conn.commit()
    conn.close()

    # Delete file from filesystem
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    flash('File deleted successfully.', 'success')
    return redirect(url_for('home'))


        # ✅ Save file info to database
    conn = get_db_connection()
    conn.execute(
            'INSERT INTO files (user, original_filename, stored_filename) VALUES (?, ?, ?)',
            (session['username'], original_filename, file_id + ".enc")
        )
    conn.commit()
    conn.close()

    flash(Markup(f'File uploaded and encrypted! <a href="/download/{file_id}" class="alert-link">Download Now</a>'), 'success')
    return redirect(url_for('home'))

    return render_template('upload.html')


# Run Flask

@app.route('/download/<file_id>')
def download(file_id):
    if 'username' not in session:
        flash('Please login to download.', 'warning')
        return redirect(url_for('login'))

    encrypted_path = os.path.join('static/uploads', f"{file_id}.enc")
    decrypted_path = os.path.join('static/uploads', f"{file_id}_decrypted")

    key = ENCRYPTION_KEY  # Match the key from upload
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES_Cipher.new(key, AES_Cipher.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
