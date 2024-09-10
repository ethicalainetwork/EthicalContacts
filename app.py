import json
import phonenumbers
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import uuid
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for the session

# In-memory storage for encrypted data (in a production environment, use a proper database)
encrypted_data_storage = {}


@app.route('/get_contacts')
def get_contacts():
    contacts = session.get('decrypted_contacts')
    if not contacts:
        return jsonify({"error": "No decrypted contact data found"}), 400
    return jsonify(contacts)

@app.route('/visualizations')
def visualizations():
    if 'decrypted_contacts' not in session:
        return redirect(url_for('index'))
    return render_template('visualizations.html') 
       
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
    return f.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data.encode()).decode())

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
    
    encrypted_data = encrypt_data(contacts, key)
    data_id = str(uuid.uuid4())
    encrypted_data_storage[data_id] = {
        'data': encrypted_data,
        'salt': salt.hex()
    }
    
    session['data_id'] = data_id
    
    return jsonify({"message": "Data encrypted successfully"})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    password = request.json.get('password')
    data_id = session.get('data_id')
    
    if not password or not data_id:
        return jsonify({"error": "Password or data ID not found"}), 400
    
    stored_data = encrypted_data_storage.get(data_id)
    if not stored_data:
        return jsonify({"error": "Encrypted data not found"}), 400
    
    encrypted_data = stored_data['data']
    salt = bytes.fromhex(stored_data['salt'])
    
    key = get_key(password, salt)
    
    try:
        decrypted_contacts = decrypt_data(encrypted_data, key)
        for contact in decrypted_contacts:
            contact['region'] = get_region_code(contact['phone_number'])
        
        session['decrypted_contacts'] = decrypted_contacts
        return jsonify({"message": "Data decrypted successfully"})
    except:
        return jsonify({"error": "Incorrect password or data corruption"}), 400

@app.route('/get_timeline_data')
def get_timeline_data():
    contacts = session.get('decrypted_contacts')
    if not contacts:
        return jsonify({"error": "No contact data found"}), 400
    
    timeline_data = defaultdict(lambda: defaultdict(int))
    
    for contact in contacts:
        date = datetime.strptime(contact['date'], "%Y-%m-%dT%H:%M:%S")
        year = date.year
        month = date.month
        region = contact['region']
        timeline_data[year][region] += 1
    
    formatted_data = [
        {
            "year": year,
            "regions": [{"name": region, "count": count} for region, count in regions.items()]
        }
        for year, regions in timeline_data.items()
    ]
    
    return jsonify(formatted_data)

@app.route('/get_region_data/<region>')
def get_region_data(region):
    contacts = session.get('decrypted_contacts')
    if not contacts:
        return jsonify({"error": "No contact data found"}), 400
    
    region_contacts = [c for c in contacts if c['region'] == region]
    
    contact_data = [
        {
            "name": f"{c['first_name']} {c['last_name']}",
            "date": c['date'],
            "phone_number": c['phone_number']
        }
        for c in region_contacts
    ]
    
    return jsonify(contact_data)

@app.route('/get_contact_details/<path:name>')
def get_contact_details(name):
    contacts = session.get('decrypted_contacts')
    if not contacts:
        return jsonify({"error": "No contact data found"}), 400
    
    contact = next((c for c in contacts if f"{c['first_name']} {c['last_name']}" == name), None)
    if not contact:
        return jsonify({"error": "Contact not found"}), 404
    
    return jsonify({
        "name": f"{contact['first_name']} {contact['last_name']}",
        "phone_number": contact['phone_number'],
        "region": contact['region'],
        "date": contact['date']
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)