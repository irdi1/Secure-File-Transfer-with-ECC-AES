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
import re

# Password validation regex to ensure strong passwords
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

# Function to encrypt the private key with the user's password
def encrypt_private_key(private_key, password):
    salt = get_random_bytes(16)  # Generate a random salt
    key = PBKDF2(password, salt, dkLen=32)  # Derive a key from the password and salt
    cipher = AES.new(key, AES.MODE_EAX)  # Create a new AES cipher
    ciphertext, tag = cipher.encrypt_and_digest(private_key.encode('utf-8'))  # Encrypt the private key
    return salt + cipher.nonce + tag + ciphertext  

# Function to decrypt the private key with the user's password
def decrypt_private_key(encrypted_private_key, password):
    salt = encrypted_private_key[:16]  # Extract the salt
    nonce = encrypted_private_key[16:32]  # Extract the nonce
    tag = encrypted_private_key[32:48]  # Extract the tag
    ciphertext = encrypted_private_key[48:]  # Extract the ciphertext
    key = PBKDF2(password, salt, dkLen=32)  # Derive the key from the password and salt
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Create a new AES cipher with the nonce
    private_key = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the private key
    return private_key.decode('utf-8')  

# Function to encrypt data using ECC public key
def encrypt_ecc(public_key, data):
    ephemeral_key = ECC.generate(curve='P-256')  # Generate an ephemeral ECC key pair
    shared_secret = ephemeral_key.d * public_key.pointQ  # Derive the shared secret
    shared_key = SHA256.new(shared_secret.x.to_bytes()).digest()  # Derive a shared key using SHA-256
    nonce = get_random_bytes(16)  # Generate a random nonce
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)  # Create a new AES cipher with the nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt the data
    return ephemeral_key.public_key().export_key(format='DER'), nonce, ciphertext, tag  

# Function to decrypt data using ECC private key
def decrypt_ecc(private_key, ephemeral_public_key_bytes, nonce, ciphertext, tag):
    ephemeral_public_key = ECC.import_key(ephemeral_public_key_bytes)  # Import the ephemeral public key
    shared_secret = private_key.d * ephemeral_public_key.pointQ  # Derive the shared secret
    shared_key = SHA256.new(shared_secret.x.to_bytes()).digest()  # Derive a shared key using SHA-256
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)  # Create a new AES cipher with the nonce
    data = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the data
    return data  # Return the decrypted data

# Route for the home page
@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

# Route for the registration page
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate password strength
        if not PASSWORD_REGEX.match(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.', 'danger')
            return redirect(url_for('register'))
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password
        ecc_key = ECC.generate(curve='P-256')  # Generate an ECC key pair
        public_key = ecc_key.public_key().export_key(format='PEM')  # Export the public key
        private_key = ecc_key.export_key(format='PEM')  # Export the private key
        encrypted_private_key = encrypt_private_key(private_key, password)  # Encrypt the private key with the password
        user = User(username=username, email=email, password=hashed_password, encrypted_private_key=encrypted_private_key, public_key=public_key)
        db.session.add(user)  # Add the user to the database
        db.session.commit()  # Commit the changes to the database
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Route for the login page
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):  # Check if the user exists and the password is correct
            login_user(user, remember=True)  # Log the user in
            flash('Login Successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

# Route for logging out
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

# Route for uploading files
@app.route("/upload", methods=['GET', 'POST'])
@login_required
def upload():
    users = User.query.filter(User.id != current_user.id).all()  # Exclude the current user from the list of users
    if request.method == 'POST':
        file = request.files['file']
        recipient_id = request.form['recipient']
        recipient = User.query.get(recipient_id)
        if file and recipient:
            recipient_key = ECC.import_key(recipient.public_key)  # Import the recipient's public key
            ephemeral_public_key_bytes, nonce, ciphertext, tag = encrypt_ecc(recipient_key, file.read())  # Encrypt the file data
            encrypted_data = ephemeral_public_key_bytes + nonce + ciphertext + tag  # Combine the encrypted data
            new_file = File(filename=file.filename, data=encrypted_data, sender_id=current_user.id, recipient_id=recipient.id)
            db.session.add(new_file)  # Add the file to the database
            db.session.commit()  # Commit the changes to the database
            flash('File successfully uploaded and encrypted!', 'success')
            return redirect(url_for('home'))
    return render_template('upload.html', users=users)

# Route for displaying received files
@app.route("/files")
@login_required
def files():
    received_files = File.query.filter_by(recipient_id=current_user.id).all()  # Get all files received by the current user
    return render_template('files.html', files=received_files)

# Route for downloading a file
@app.route("/download/<int:file_id>", methods=['GET', 'POST'])
@login_required
def download(file_id):
    if request.method == 'GET':
        return render_template('password_prompt.html', file_id=file_id)

    if request.method == 'POST':
        password = request.form['password']
        file_data = File.query.get_or_404(file_id)
        if file_data.recipient_id != current_user.id:
            flash('You do not have permission to download this file.', 'danger')
            return redirect(url_for('home'))

        # Fetch the encrypted private key from the database
        user = User.query.get(current_user.id)
        encrypted_private_key = user.encrypted_private_key
        
        try:
            # Decrypt the private key using the provided password
            decrypted_private_key = decrypt_private_key(encrypted_private_key, password)
        except ValueError:
            flash('Invalid password. Please try again.', 'danger')
            return redirect(url_for('download', file_id=file_id))

        private_key = ECC.import_key(decrypted_private_key)

        ephemeral_public_key_bytes = file_data.data[:91]  # DER-encoded ECC public key is 91 bytes for P-256
        nonce = file_data.data[91:107]
        ciphertext = file_data.data[107:-16]
        tag = file_data.data[-16:]

        decrypted_data = decrypt_ecc(private_key, ephemeral_public_key_bytes, nonce, ciphertext, tag)
        
        # Send the decrypted file data directly
        response = send_file(io.BytesIO(decrypted_data), download_name=file_data.filename, as_attachment=True)
        response.headers["Refresh"] = "0; url=" + url_for('files')
        return response

# Route for downloading the encrypted file
@app.route("/download_encrypted/<int:file_id>")
@login_required
def download_encrypted(file_id):
    file_data = File.query.get_or_404(file_id)
    if file_data.recipient_id != current_user.id:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('home'))

    return send_file(io.BytesIO(file_data.data), download_name=file_data.filename, as_attachment=True)
