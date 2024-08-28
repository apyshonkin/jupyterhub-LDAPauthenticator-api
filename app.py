import os
import sys
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL
import jwt
from datetime import datetime, timedelta
import logging

app = Flask(__name__)

# Configurations from environment variables
LDAP_SERVER = os.getenv('LDAP_SERVER', 'ldap://localhost')
BIND_USER = os.getenv('BIND_USER', 'cn=admin,dc=example,dc=com')
BIND_PASSWORD = os.getenv('BIND_PASSWORD', 'admin_password')
BASE_DN = os.getenv('BASE_DN', 'dc=example,dc=com')
SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 8080))

# Setup logging to stdout
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# JWT creation function
def create_jwt_token(username):
    expiration = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({'username': username, 'exp': expiration}, SECRET_KEY, algorithm='HS256')
    return token

# Check if the password has expired
def is_password_expired(user_entry):
    pwd_last_set = user_entry['pwdLastSet'].value
    max_pwd_age = int(user_entry['maxPwdAge'].value)
    password_last_set_date = datetime.fromtimestamp(pwd_last_set)
    expiration_date = password_last_set_date + timedelta(seconds=max_pwd_age)
    return datetime.now() > expiration_date

# Search for user in LDAP
def search_for_user(conn, username):
    conn.search(BASE_DN, f'(uid={username})', attributes=['cn', 'pwdLastSet', 'maxPwdAge'])
    return conn.entries

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.json.get('username')
    password = request.json.get('password')

    logging.info(f"Authentication attempt for user: {username}")

    if not username or not password:
        logging.warning(f"Authentication failed for user: {username} - Missing credentials")
        return jsonify({'authenticated': False, 'error': 'Username or password missing'}), 400

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, BIND_USER, BIND_PASSWORD, auto_bind=True)

    user_entries = search_for_user(conn, username)
    if not user_entries:
        logging.warning(f"Authentication failed for user: {username} - User not found")
        return jsonify({'authenticated': False, 'error': 'User not found'}), 404

    user_entry = user_entries[0]
    if is_password_expired(user_entry):
        logging.warning(f"Authentication failed for user: {username} - Password expired")
        return jsonify({'authenticated': False, 'error': 'Password expired'}), 403

    user_dn = user_entry.entry_dn
    user_conn = Connection(server, user_dn, password, auto_bind=True)

    if user_conn.bind():
        token = create_jwt_token(username)
        logging.info(f"Authentication successful for user: {username}")
        return jsonify({'authenticated': True, 'token': token})
    else:
        logging.warning(f"Authentication failed for user: {username} - Invalid credentials")
        return jsonify({'authenticated': False, 'error': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(host=HOST, port=PORT)
