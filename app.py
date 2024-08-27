from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os
import re
from dotenv import load_dotenv
from twilio.rest import Client
import logging

# Load environment variables from .env file
load_dotenv()

# Debugging: Print environment variables
print("TWILIO_ACCOUNT_SID:", os.getenv('TWILIO_ACCOUNT_SID'))
print("TWILIO_AUTH_TOKEN:", os.getenv('TWILIO_AUTH_TOKEN'))
print("PHONE_NUMBER:", os.getenv('PHONE_NUMBER'))

# Enable debug logging for Twilio
logging.basicConfig(level=logging.DEBUG)

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/cryptography'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)  # Initialize SQLAlchemy with the Flask app

# Define the database model for storing encrypted messages
class EncryptedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    encrypted_data = db.Column(db.String(500), nullable=False)  # Encrypted message
    key = db.Column(db.String(100), nullable=False)  # Encryption key

# Route for the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for encryption page
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        message = request.form['message']  # Get message from the form
        phone_number = request.form['phone_number']  # Get phone number from the form

        # Validate the phone number
        if not validate_phone_number(phone_number):
            flash('Invalid phone number format. Please use the format +1234567890.', 'danger')
            return redirect(url_for('encrypt'))
        
        # Generate encryption key and encrypt the message
        key = generate_key()
        encrypted_message = encrypt_message(message, key)
        
        # Save the encrypted message and key to the database
        new_message = EncryptedMessage(encrypted_data=encrypted_message, key=key)
        db.session.add(new_message)
        db.session.commit()
        
        # Try to send the encrypted message and key via SMS
        try:
            send_sms(phone_number, f'Your encrypted message: {encrypted_message} Key: {key}')
            flash('Message encrypted and sent via SMS successfully!', 'success')
        except Exception as e:
            flash(f'Failed to send SMS: {e}', 'danger')
            return redirect(url_for('encrypt'))
        
        return redirect(url_for('index'))
    return render_template('encrypt.html')

# Route for decryption page
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        encrypted_message = request.form['encrypted_message']  # Get encrypted message from the form
        key = request.form['key']  # Get encryption key from the form
        
        # Try to decrypt the message
        try:
            decrypted_message = decrypt_message(encrypted_message, key)
            flash(f'Decrypted message: {decrypted_message}', 'success')
        except Exception as e:
            flash('Decryption failed. Please check your encrypted message and key.', 'danger')
        return redirect(url_for('index'))
    return render_template('decrypt.html')

# Generate a new encryption key
def generate_key():
    return Fernet.generate_key().decode()

# Encrypt the message using the provided key
def encrypt_message(message, key):
    fernet = Fernet(key.encode())
    return fernet.encrypt(message.encode()).decode()

# Decrypt the message using the provided key
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key.encode())
    return fernet.decrypt(encrypted_message.encode()).decode()

# Validate the phone number format
def validate_phone_number(phone_number):
    pattern = re.compile(r'^\+\d{1,15}$')
    return pattern.match(phone_number)

# Send an SMS using the Twilio API
def send_sms(to, body):
    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
    auth_token= os.getenv('TWILIO_AUTH_TOKEN')
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        body=body,
        from_=os.getenv('PHONE_NUMBER'),
        to=to
    )

# Main entry point of the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
