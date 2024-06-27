import unittest
from app import app, db, bcrypt
from models import User, File
from flask import session
import io

class SecureFileExchangeTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        self.bcrypt = bcrypt

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def register_user(self, username, email, password):
        return self.app.post('/register', data=dict(
            username=username,
            email=email,
            password=password
        ), follow_redirects=True)

    def login_user(self, email, password):
        return self.app.post('/login', data=dict(
            email=email,
            password=password
        ), follow_redirects=True)

    def upload_file(self, file_content, recipient_id):
        return self.app.post('/upload', data=dict(
            file=(io.BytesIO(file_content.encode()), 'test.txt'),
            recipient=recipient_id
        ), follow_redirects=True)

    def test_user_registration(self):
        response = self.register_user('testuser', 'test@example.com', 'password')
        self.assertIn(b'Your account has been created!', response.data)
        
        # Test registering with an existing email
        response = self.register_user('testuser2', 'test@example.com', 'password')
        self.assertIn(b'This email is already registered.', response.data)

    def test_user_login(self):
        self.register_user('testuser', 'test@example.com', 'password')
        response = self.login_user('test@example.com', 'password')
        self.assertIn(b'Welcome', response.data)
        
        # Test login with incorrect password
        response = self.login_user('test@example.com', 'wrongpassword')
        self.assertIn(b'Login Unsuccessful. Please check email and password', response.data)

    def test_file_upload(self):
        self.register_user('testuser', 'test@example.com', 'password')
        self.login_user('test@example.com', 'password')
        
        # Register another user to send file to
        self.register_user('recipient', 'recipient@example.com', 'password')
        recipient = User.query.filter_by(email='recipient@example.com').first()
        
        # Test file upload
        response = self.upload_file('This is a test file.', recipient.id)
        self.assertIn(b'File successfully uploaded and encrypted!', response.data)

    def test_file_download_decrypted(self):
        self.register_user('testuser', 'test@example.com', 'password')
        self.login_user('test@example.com', 'password')
        
        # Register another user to send file to
        self.register_user('recipient', 'recipient@example.com', 'password')
        recipient = User.query.filter_by(email='recipient@example.com').first()
        
        # Upload file
        self.upload_file('This is a test file.', recipient.id)
        file = File.query.filter_by(recipient_id=recipient.id).first()
        
        # Login as recipient and download file
        self.login_user('recipient@example.com', 'password')
        response = self.app.get(f'/download/{file.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'This is a test file.', response.data)

    def test_file_download_encrypted(self):
        self.register_user('testuser', 'test@example.com', 'password')
        self.login_user('test@example.com', 'password')
        
        # Register another user to send file to
        self.register_user('recipient', 'recipient@example.com', 'password')
        recipient = User.query.filter_by(email='recipient@example.com').first()
        
        # Upload file
        self.upload_file('This is a test file.', recipient.id)
        file = File.query.filter_by(recipient_id=recipient.id).first()
        
        # Login as recipient and download encrypted file
        self.login_user('recipient@example.com', 'password')
        response = self.app.get(f'/download_encrypted/{file.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(file.data, response.data)

if __name__ == '__main__':
    unittest.main()
