from flask import Flask, request, redirect, make_response, g, session, abort, render_template
from config import Config
from functools import wraps
from cryptography.fernet import Fernet
from datetime import datetime
from werkzeug.utils import secure_filename
import bcrypt
import json
import time
import logging
import secrets
import html
import re
import os
import os.path

# --- DATA PERSISTENCE CLASSES ---

def save_user(user_data):
    # Requirement: File-based storage using JSON
    users = load_all_users()
    users[user_data['username']] = user_data
    with open(Config.USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_all_users():
    if not os.path.exists(Config.USERS_FILE):
        return {}
    with open(Config.USERS_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

class EncryptedStorage:
    def __init__(self, key_file='secret.key'):
        try:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def save_encrypted(self, filename, data):
        json_data = json.dumps(data)
        encrypted = self.cipher.encrypt(json_data.encode())
        with open(filename, 'wb') as f:
            f.write(encrypted)

    def load_encrypted(self, filename):
        with open(filename, 'rb') as f:
            encrypted = f.read()
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

class SessionManager:
    def __init__(self, timeout=1800):
        self.timeout = timeout
        self.sessions_file = 'data/sessions.json'

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        session_data = {
            'token': token,
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        sessions = self.load_sessions()
        sessions[token] = session_data
        self.save_sessions(sessions)
        return token

    def validate_session(self, token):
        sessions = self.load_sessions()
        if token not in sessions:
            return None
        session_data = sessions[token]
        if time.time() - session_data['last_activity'] > self.timeout:
            self.destroy_session(token)
            return None
        session_data['last_activity'] = time.time()
        sessions[token] = session_data
        self.save_sessions(sessions)
        return session_data

    def destroy_session(self, token):
        sessions = self.load_sessions()
        if token in sessions:
            del sessions[token]
            self.save_sessions(sessions)

    def load_sessions(self):
        if not os.path.exists(self.sessions_file):
            return {}
        with open(self.sessions_file, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}

    def save_sessions(self, sessions):
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f, indent=4)

class SecurityLogger:
    def __init__(self, log_file='logs/security.log'):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        # Avoid duplicate handlers if re-initialized
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'details': details,
            'severity': severity
        }
        message = json.dumps(log_entry)
        if severity == 'CRITICAL':
            self.logger.critical(message)
        elif severity == 'ERROR':
            self.logger.error(message)
        elif severity == 'WARNING':
            self.logger.warning(message)
        else:
            self.logger.info(message)

# --- HELPER FUNCTIONS & DECORATORS ---

def validate_username(username):
    # Requirement: 3-20 chars, alphanumeric + underscore 
    return bool(re.match(r"^\w{3,20}$", username))

def validate_password_strength(password):
    # Requirement: Min 12 chars
    if len(password) < 12:
        return False
    # Complexity requirements
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_spec = any(c in "!@#$%^&*" for c in password)
    return all([has_upper, has_lower, has_digit, has_spec])

def register_user(username, email, password):
    # Validate inputs
    if not validate_username(username):
        return {"error": "Invalid username"}
    if not validate_password_strength(password):
        return {"error": "Password does not meet requirements"}
    # Hash password
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    # Store user (file-based)
    user = {
        "username": username,
        "email": email,
        "password_hash": hashed.decode('utf-8'),
        "created_at": time.time(),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": None
    }
    save_user(user)
    return {"success": True}

# --- INITIALIZATION ---

app = Flask(__name__)
app.config.from_object(Config)

# Initialize your management objects
storage = EncryptedStorage()
session_manager = SessionManager(timeout=Config.SESSION_TIMEOUT)
security_log = SecurityLogger(log_file=Config.SECURITY_LOG)

# --- ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get data from the HTML form
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Use the helper function you already wrote
        result = register_user(username, email, password)
        
        if "error" in result:
            # If validation fails, show the error on the registration page
            return render_template('register.html', error=result['error'])
        
        # Success! Send them to the login page
        return redirect('/login')
    
    # If it's a GET request, just show the form
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password_input = request.form.get('password')
        
        if not username or not password_input:
             return render_template('login.html', error="Missing credentials")

        password_bytes = password_input.encode('utf-8')
        users = load_all_users()
        user = users.get(username)
        
        # Requirement: Check password against bcrypt hash
        if user and bcrypt.checkpw(password_bytes, user['password_hash'].encode('utf-8')):
            # Create a session using your SessionManager
            token = session_manager.create_session(username)
            
            # Create response and set a SECURE cookie
            response = make_response(redirect('/dashboard'))
            response.set_cookie(
                'session_token', 
                token, 
                httponly=True, 
                secure=True, 
                samesite='Strict'
            )
            
            security_log.log_event('LOGIN_SUCCESS', username, {'action': 'login'})
            return response
        
        # Log failure and show error
        security_log.log_event('LOGIN_FAILED', username, {'reason': 'Invalid credentials'}, severity='WARNING')
        return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # Basic check for Week 2 functionality
    token = request.cookies.get('session_token')
    session_data = session_manager.validate_session(token) if token else None
    
    if not session_data:
        return redirect('/login')
    
    return render_template('dashboard.html', username=session_data['user_id'])

if __name__ == '__main__':
    # Ensure necessary directories exist for Week 2
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    print("Server is starting...")

    app.run(debug=True, port=5000)