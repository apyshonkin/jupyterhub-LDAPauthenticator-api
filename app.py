import os
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE
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

# Setup logging
logging.basicConfig(filename='ldapauth-api.log', level=logging.INFO)

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

@app.route('/create-user', methods=['POST'])
def create_user():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    full_name = request.json.get('full_name')

    if not username or not password or not email or not full_name:
        return jsonify({'success': False, 'error': 'Missing parameters'}), 400

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, BIND_USER, BIND_PASSWORD, auto_bind=True)

    user_dn = f"cn={username},{BASE_DN}"

    try:
        conn.add(
            dn=user_dn,
            object_class=['inetOrgPerson', 'posixAccount'],
            attributes={
                'cn': full_name,
                'sn': full_name.split()[-1],
                'uid': username,
                'userPassword': password,
                'mail': email,
                'homeDirectory': f'/home/{username}',
                'uidNumber': '10000',
                'gidNumber': '10000',
                'loginShell': '/bin/bash',
            }
        )
        logging.info(f"User {username} created successfully")
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        logging.error(f"Failed to create user {username}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete-user', methods=['POST'])
def delete_user():
    username = request.json.get('username')

    if not username:
        return jsonify({'success': False, 'error': 'Missing username'}), 400

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, BIND_USER, BIND_PASSWORD, auto_bind=True)

    user_dn = f"cn={username},{BASE_DN}"

    try:
        conn.delete(user_dn)
        logging.info(f"User {username} deleted successfully")
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        logging.error(f"Failed to delete user {username}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/modify-group', methods=['POST'])
def modify_group():
    username = request.json.get('username')
    group_dn = request.json.get('group_dn')
    action = request.json.get('action')  # 'add' or 'remove'

    if not username or not group_dn or not action:
        return jsonify({'success': False, 'error': 'Missing parameters'}), 400

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, BIND_USER, BIND_PASSWORD, auto_bind=True)

    user_dn = f"cn={username},{BASE_DN}"

    try:
        if action == 'add':
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
        elif action == 'remove':
            conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400

        logging.info(f"User {username} {action}ed to group {group_dn} successfully")
        return jsonify({'success': True, 'message': f'User {action}ed to group successfully'})
    except Exception as e:
        logging.error(f"Failed to {action} user {username} to group {group_dn}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
