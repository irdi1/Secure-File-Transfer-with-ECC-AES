import re
from flask import render_template, url_for, flash, redirect, request, send_file, session
from app import app, db, bcrypt
from models import User, File
from flask_login import login_user, current_user, logout_user, login_required
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import os
import io

# Password validation regex
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

def encrypt_private_key(private_key, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key.encode('utf-8'))
    return salt + cipher.nonce + tag + ciphertext

def decrypt_private_key(encrypted_private_key, password):
    salt = encrypted_private_key[:16]
    nonce = encrypted_private_key[16:32]
    tag = encrypted_private_key[32:48]
    ciphertext = encrypted_private_key[48:]
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    private_key = cipher.decrypt_and_verify(ciphertext, tag)
    return private_key.decode('utf-8')

def encrypt_ecc(public_key, data):
    # Generate an ephemeral key pair for ECDH
    ephemeral_key = ECC.generate(curve='P-256')
    shared_secret = ephemeral_key.d * public_key.pointQ
    shared_key = SHA256.new(shared_secret.x.to_bytes()).digest()
    nonce = get_random_bytes(16)
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ephemeral_key.public_key().export_key(format='DER'), nonce, ciphertext, tag

def decrypt_ecc(private_key, ephemeral_public_key_bytes, nonce, ciphertext, tag):
    # Load the ephemeral public key
    ephemeral_public_key = ECC.import_key(ephemeral_public_key_bytes)
    shared_secret = private_key.d * ephemeral_public_key.pointQ
    shared_key = SHA256.new(shared_secret.x.to_bytes()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not PASSWORD_REGEX.match(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        ecc_key = ECC.generate(curve='P-256')
        public_key = ecc_key.public_key().export_key(format='PEM')
        private_key = ecc_key.export_key(format='PEM')
        encrypted_private_key = encrypt_private_key(private_key, password)
        user = User(username=username, email=email, password=hashed_password, encrypted_private_key=encrypted_private_key, public_key=public_key)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            # Decrypt private key for use in the session
            decrypted_private_key = decrypt_private_key(user.encrypted_private_key, password)
            # Store decrypted private key in the session
            session['private_key'] = decrypted_private_key
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/upload", methods=['GET', 'POST'])
@login_required
def upload():
    users = User.query.filter(User.id != current_user.id).all()  # Exclude the current user from the list
    if request.method == 'POST':
        file = request.files['file']
        recipient_id = request.form['recipient']
        recipient = User.query.get(recipient_id)
        if file and recipient:
            recipient_key = ECC.import_key(recipient.public_key)
            ephemeral_public_key_bytes, nonce, ciphertext, tag = encrypt_ecc(recipient_key, file.read())
            encrypted_data = ephemeral_public_key_bytes + nonce + ciphertext + tag
            new_file = File(filename=file.filename, data=encrypted_data, sender_id=current_user.id, recipient_id=recipient.id)
            db.session.add(new_file)
            db.session.commit()
            flash('File successfully uploaded and encrypted!', 'success')
            return redirect(url_for('home'))
    return render_template('upload.html', users=users)

@app.route("/files")
@login_required
def files():
    received_files = File.query.filter_by(recipient_id=current_user.id).all()
    return render_template('files.html', files=received_files)

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    file_data = File.query.get_or_404(file_id)
    if file_data.recipient_id != current_user.id:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('home'))

    private_key = ECC.import_key(session['private_key'])
    ephemeral_public_key_bytes = file_data.data[:91]  # DER-encoded ECC public key is 91 bytes for P-256
    nonce = file_data.data[91:107]
    ciphertext = file_data.data[107:-16]
    tag = file_data.data[-16:]

    decrypted_data = decrypt_ecc(private_key, ephemeral_public_key_bytes, nonce, ciphertext, tag)
    return send_file(io.BytesIO(decrypted_data), download_name=file_data.filename, as_attachment=True)

@app.route("/download_encrypted/<int:file_id>")
@login_required
def download_encrypted(file_id):
    file_data = File.query.get_or_404(file_id)
    if file_data.recipient_id != current_user.id:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('home'))

    return send_file(io.BytesIO(file_data.data), download_name=file_data.filename, as_attachment=True)
