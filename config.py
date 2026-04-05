import os
import secrets

class Config:
    # 1. Essential Flask Security
    # Use secrets.token_urlsafe(32) as recommended 
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    
    # 2. Authentication & Session Settings
    # Project requires bcrypt rounds >= 12 [cite: 6]
    BCRYPT_LOG_ROUNDS = 12 
    # Project requires 30 minute timeout (1800 seconds) 
    SESSION_TIMEOUT = 1800 
    
    # 3. File-Based Storage Paths [cite: 4, 28]
    DATA_DIR = 'data'
    USERS_FILE = os.path.join(DATA_DIR, 'users.json')
    SESSIONS_FILE = os.path.join(DATA_DIR, 'sessions.json')
    
    # 4. Logging Paths [cite: 20, 28]
    LOG_DIR = 'logs'
    SECURITY_LOG = os.path.join(LOG_DIR, 'security.log')
    
    # 5. File Upload Restrictions [cite: 13]
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB Limit
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}