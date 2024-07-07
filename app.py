from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/cryptography'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class EncryptedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_data = db.Column(db.String(500), nullable=False)
    key = db.Column(db.String(100), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        message = request.form['message']
        phone_number = request.form['phone_number']
        if not validate_phone_number(phone_number):
            flash('Invalid phone number format. Please use the format +1234567890.', 'danger')
            return redirect(url_for('encrypt'))
        
        key = generate_key()
        encrypted_message = encrypt_message(message, key)
        new_message = EncryptedMessage(encrypted_data=encrypted_message, key=key)
        db.session.add(new_message)
        db.session.commit()
        
        try:
            send_sms(phone_number, f'Your encrypted message: {encrypted_message} Key: {key}')
            flash('Message encrypted and sent via SMS successfully!', 'success')
        except Exception as e:
            flash(f'Failed to send SMS: {e}', 'danger')
            return redirect(url_for('encrypt'))
        
        return redirect(url_for('index'))
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        encrypted_message = request.form['encrypted_message']
        key = request.form['key']
        try:
            decrypted_message = decrypt_message(encrypted_message, key)
            flash(f'Decrypted message: {decrypted_message}', 'success')
        except Exception as e:
            flash('Decryption failed. Please check your encrypted message and key.', 'danger')
        return redirect(url_for('index'))
    return render_template('decrypt.html')

def generate_key():
    return Fernet.generate_key().decode()

def encrypt_message(message, key):
    fernet = Fernet(key.encode())
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key.encode())
    return fernet.decrypt(encrypted_message.encode()).decode()

def validate_phone_number(phone_number):
    pattern = re.compile(r'^\+\d{1,15}$')
    return pattern.match(phone_number)

from twilio.rest import Client

def send_sms(to, body):
    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
    auth_token = os.getenv('TWILIO_AUTH_TOKEN')
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        body=body,
        from_=os.getenv('PHONE_NUMBER'),
        to=to
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
