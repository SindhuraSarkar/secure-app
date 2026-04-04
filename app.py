from flask import Flask, request, redirect, make_response, g, session, abort, render_template
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
        session = {
            'token': token,
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        sessions = self.load_sessions()
        sessions[token] = session
        self.save_sessions(sessions)
        return token

    def validate_session(self, token):
        sessions = self.load_sessions()
        if token not in sessions:
            return None
        session = sessions[token]
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy_session(token)
            return None
        session['last_activity'] = time.time()
        sessions[token] = session
        self.save_sessions(sessions)
        return session

    def destroy_session(self, token):
        sessions = self.load_sessions()
        if token in sessions:
            del sessions[token]
            self.save_sessions(sessions)

class SecurityLogger:
    def __init__(self, log_file='logs/security.log'):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
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
        if severity == 'CRITICAL':
            self.logger.critical(json.dumps(log_entry))
        elif severity == 'ERROR':
            self.logger.error(json.dumps(log_entry))
        elif severity == 'WARNING':
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))

# --- HELPER FUNCTIONS & DECORATORS ---

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