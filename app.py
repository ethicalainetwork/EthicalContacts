import json
import phonenumbers
from flask import Flask, render_template, request, jsonify, session
from datetime import datetime
import html
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for the session
import phonenumbers

def get_region_code(phone_number):
    # List of possible country codes to try
    country_codes = ['', '1', '44', '91', '86', '81', '49', '33', '39', '7', '34', '31', '46']
    
    # Remove any non-digit characters
    cleaned_number = ''.join(filter(str.isdigit, phone_number))
    
    for country_code in country_codes:
        # Try with the original number
        try:
            parsed_number = phonenumbers.parse(f"+{country_code}{cleaned_number}", None)
            if phonenumbers.is_valid_number(parsed_number):
                return phonenumbers.region_code_for_number(parsed_number)
        except phonenumbers.NumberParseException:
            pass

        # Try without leading zero
        if cleaned_number.startswith('0'):
            try:
                parsed_number = phonenumbers.parse(f"+{country_code}{cleaned_number[1:]}", None)
                if phonenumbers.is_valid_number(parsed_number):
                    return phonenumbers.region_code_for_number(parsed_number)
            except phonenumbers.NumberParseException:
                pass

        # Try with adding a zero
        try:
            parsed_number = phonenumbers.parse(f"+{country_code}0{cleaned_number}", None)
            if phonenumbers.is_valid_number(parsed_number):
                return phonenumbers.region_code_for_number(parsed_number)
        except phonenumbers.NumberParseException:
            pass

    return "Unknown"

# The rest of your Flask application code remains the same

def generate_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def get_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        data = json.load(file)
        contacts = data['contacts']['list']
        session['contacts'] = contacts
        return jsonify({"message": "File uploaded successfully"})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    password = request.json.get('password')
    contacts = session.get('contacts')
    
    if not password or not contacts:
        return jsonify({"error": "Password or contacts not found"}), 400
    
    key, salt = generate_key(password)
    
    # Encrypt sensitive data
    for contact in contacts:
        contact['first_name'] = encrypt_data(contact['first_name'], key)
        contact['last_name'] = encrypt_data(contact['last_name'], key)
        contact['phone_number'] = encrypt_data(contact['phone_number'], key)
    
    session['contacts'] = contacts
    session['salt'] = salt.hex()  # Store salt in session for later decryption
    
    return jsonify({"message": "Data encrypted successfully"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    password = request.json.get('password')
    contacts = session.get('contacts')
    salt = bytes.fromhex(session.get('salt', ''))
    
    if not password or not contacts or not salt:
        return jsonify({"error": "Password, contacts, or salt not found"}), 400
    
    key = get_key(password, salt)
    
    try:
        # Decrypt sensitive data
        decrypted_contacts = []
        for contact in contacts:
            decrypted_contact = contact.copy()
            decrypted_contact['first_name'] = decrypt_data(contact['first_name'], key)
            decrypted_contact['last_name'] = decrypt_data(contact['last_name'], key)
            decrypted_contact['phone_number'] = decrypt_data(contact['phone_number'], key)
            decrypted_contact['region'] = get_region_code(decrypted_contact['phone_number'])
            decrypted_contacts.append(decrypted_contact)
        
        return jsonify(decrypted_contacts)
    except:
        return jsonify({"error": "Incorrect password or data corruption"}), 400

@app.route('/get_regions')
def get_regions():
    contacts = session.get('contacts')
    if not contacts:
        return jsonify({"error": "No contact data found"}), 400
    
    regions = set()
    for contact in contacts:
        regions.add(get_region_code(contact['phone_number']))
    
    return jsonify(list(regions))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)