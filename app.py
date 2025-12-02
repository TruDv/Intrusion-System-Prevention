import os
import json
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

# Database and Server Imports
from flask import Flask, request, jsonify, g, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

# Security Imports
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets 

# --- Configuration ---
class Config:
    # Database Configuration
    # Uses SQLite (intrusion_system.db)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///intrusion_system.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_strong_secret_key_for_demonstrator_only') 
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRY_DAYS = 7
    
    # MFA Settings
    MFA_CODE_EXPIRY_SECONDS = 300 # 5 minutes
    
    # Intrusion Prevention (Rate Limiter) Settings
    MAX_LOGIN_ATTEMPTS = 5
    RATE_LIMIT_WINDOW_SECONDS = 60 # Window to track failures

# --- Flask App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS (necessary for frontend communication, even though Flask serves the HTML)
CORS(app)

# Database Initialization
db = SQLAlchemy(app)

# --- Database Models ---

class User(db.Model):
    """Stores user accounts, roles, and MFA data."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')
    
    # MFA Fields
    mfa_code = db.Column(db.String(6), nullable=True)
    mfa_code_expiry = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SecurityLog(db.Model):
    """Simulates logging of system events or anomalies."""
    id = db.Column(db.Integer, primary_key=True)
    # Always store timestamps as UTC
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc)) 
    level = db.Column(db.String(20))
    message = db.Column(db.String(500))
    source_ip = db.Column(db.String(45), nullable=True)
    log_type = db.Column(db.String(50))

# --- Helper Functions ---

def log_security_event(level, message, log_type):
    """Adds an entry to the SecurityLog table."""
    source_ip = request.remote_addr if request else 'N/A'
    
    log = SecurityLog(
        level=level, 
        message=message, 
        source_ip=source_ip, 
        log_type=log_type
    )
    db.session.add(log)
    db.session.commit()

def generate_jwt_token(user):
    """Generates an access token with user data and role."""
    now = datetime.now(timezone.utc)
    # Token payload includes username, ID, role, and expiration (exp)
    payload = {
        'exp': now + timedelta(days=app.config['JWT_EXPIRY_DAYS']),
        'iat': now,
        'username': user.username,
        'user_id': user.id,
        'role': user.role
    }
    
    token = jwt.encode(
        payload, 
        app.config['SECRET_KEY'], 
        algorithm=app.config['JWT_ALGORITHM']
    )
    return token

def token_required(roles=[]):
    """
    Decorator to protect routes and enforce role-based access control (RBAC).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]

            if not token:
                log_security_event('WARNING', 'Access attempt without token.', 'AUTHZ_FAILURE')
                return jsonify({'message': 'Authorization Token is missing!'}), 401
            
            try:
                data = jwt.decode(
                    token, 
                    app.config['SECRET_KEY'],
                    algorithms=[app.config['JWT_ALGORITHM']]
                )
                current_user = User.query.filter_by(username=data['username']).first()
                
                if current_user is None:
                    log_security_event('CRITICAL', f'Invalid token (user {data.get("username", "Unknown")} not found).', 'AUTHZ_FAILURE')
                    return jsonify({'message': 'Token user not found.'}), 401

                # Role Check (RBAC enforcement)
                if roles and current_user.role not in roles:
                    log_security_event(
                        'CRITICAL', 
                        f'RBAC Violation: User {current_user.username} (Role: {current_user.role}) attempted unauthorized access to a protected resource.', 
                        'AUTHZ_FAILURE'
                    )
                    return jsonify({'message': 'Insufficient privileges for this resource (RBAC Violation).'}), 403

            except jwt.ExpiredSignatureError:
                log_security_event('WARNING', 'Access attempt with expired token.', 'AUTHZ_FAILURE')
                return jsonify({'message': 'Token has expired.'}), 401
            except jwt.InvalidTokenError:
                log_security_event('CRITICAL', 'Access attempt with invalid token.', 'AUTHZ_FAILURE')
                return jsonify({'message': 'Token is invalid.'}), 401
            except Exception as e:
                log_security_event('ERROR', f'Token processing error: {str(e)}', 'AUTHZ_FAILURE')
                return jsonify({'message': 'Token processing error.'}), 401

            g.current_user = current_user
            return f(*args, **kwargs)
        return decorated
    return decorator

def check_rate_limit(username=None):
    """
    Checks if a login attempt is rate-limited based on failure history for the IP or username.
    Returns True if rate-limited (blocked), False otherwise.
    """
    source_ip = request.remote_addr
    time_window = datetime.now(timezone.utc) - timedelta(seconds=app.config['RATE_LIMIT_WINDOW_SECONDS'])
    
    # 1. Check IP-based failures
    ip_failures = SecurityLog.query.filter(
        SecurityLog.log_type == 'AUTH_FAILURE',
        SecurityLog.source_ip == source_ip,
        SecurityLog.timestamp >= time_window
    ).count()

    if ip_failures >= app.config['MAX_LOGIN_ATTEMPTS']:
        log_security_event('ALERT', f'Rate Limit Triggered. IP {source_ip} blocked.', 'RATE_LIMIT')
        return True
    
    # 2. Check Username-based failures
    if username:
        user_failures = SecurityLog.query.filter(
            SecurityLog.log_type == 'AUTH_FAILURE',
            SecurityLog.message.like(f'%User: {username}%'),
            SecurityLog.timestamp >= time_window
        ).count()
        
        if user_failures >= app.config['MAX_LOGIN_ATTEMPTS']:
            log_security_event('ALERT', f'Rate Limit Triggered. Username {username} blocked.', 'RATE_LIMIT')
            return True

    return False

# --- Database Initialization Function ---

def create_db_and_users():
    """Creates the database and adds an initial admin user for testing."""
    # This function must be run within the application context.
    
    # NOTE: db.drop_all() is included for a clean demo environment, 
    # but should be removed in a non-ephemeral/production environment.
    db.drop_all() 
    db.create_all()

    # Create default users for easy testing
    if User.query.filter_by(username='admin').first() is None:
        admin_user = User(username='admin', email='admin@demo.com', role='admin')
        admin_user.set_password('securepassword')
        db.session.add(admin_user)
        print("Default Admin user created: admin/securepassword")
        
    if User.query.filter_by(username='finance').first() is None:
        finance_user = User(username='finance', email='finance@demo.com', role='finance')
        finance_user.set_password('securepassword')
        db.session.add(finance_user)
        print("Default Finance user created: finance/securepassword")
        
    if User.query.filter_by(username='user1').first() is None:
        standard_user = User(username='user1', email='user1@demo.com', role='user')
        standard_user.set_password('securepassword')
        db.session.add(standard_user)
        print("Default Standard user created: user1/securepassword")

    db.session.commit()
    log_security_event('INFO', 'Database initialized and default users created.', 'SYSTEM_INIT')


# --- Application Routes ---

@app.route('/', methods=['GET'])
def index():
    """Serves the main HTML client (index.html)."""
    return render_template('index.html') 

@app.route('/register', methods=['POST'])
def register_user():
    """Route to create a new user account."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not all([username, password, email]):
        return jsonify({'message': 'Missing required fields (username, password, email)'}), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists.'}), 409

    # Assign 'admin' role for easy testing with the frontend
    new_user = User(username=username, email=email, role='admin')
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    
    log_security_event('INFO', f'New user registered: {username} with role admin.', 'USER_CREATED')
    return jsonify({'message': 'User registered successfully. Default role is "admin".'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Step 1: Authenticates user and initiates MFA by generating a code."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'message': 'Missing username or password.'}), 400

    # IPS Check: Block if rate limit is exceeded
    if check_rate_limit(username):
        return jsonify({'message': 'Too many failed login attempts. Account temporarily locked (Rate Limit).'}), 429

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Password successful: generate MFA code
        mfa_code = secrets.token_hex(3).upper() # 6-digit hex code
        user.mfa_code = mfa_code
        user.mfa_code_expiry = datetime.now(timezone.utc) + timedelta(seconds=app.config['MFA_CODE_EXPIRY_SECONDS'])
        db.session.commit()
        
        log_security_event('INFO', f'User {username} authenticated primary password. Awaiting MFA.', 'AUTH_PENDING_MFA')
        
        # NOTE: Print MFA code to console for demo (Visible in Render logs)
        print(f"\n--- MFA Code for {username}: {mfa_code} --- (Expires in 5 minutes)\n")

        return jsonify({
            'message': 'Password correct. MFA code sent. Proceed to /verify-mfa',
            'status': 'pending_mfa',
            'username': user.username,
            # *** CRITICAL FOR FRONTEND DEMO ***
            'mfa_code_for_demo': mfa_code 
            
        }), 200

    # Login failed (user not found or wrong password)
    log_security_event('WARNING', f'Login failed for User: {username}.', 'AUTH_FAILURE')
    return jsonify({'message': 'Invalid credentials or account blocked by IPS.'}), 401

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    """Step 2: Verifies the MFA code and issues the final JWT access token."""
    data = request.get_json()
    username = data.get('username')
    otp_code = data.get('otp_code')

    if not all([username, otp_code]):
        return jsonify({'message': 'Missing username or OTP code.'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message': 'User not found.'}), 404
        
    now = datetime.now(timezone.utc)
    
    # Must convert the DB time to be timezone-aware (UTC) for comparison with 'now'
    mfa_expiry_aware = None
    if user.mfa_code_expiry:
        mfa_expiry_aware = user.mfa_code_expiry.replace(tzinfo=timezone.utc)

    # Check MFA code and expiry
    if user.mfa_code == otp_code and mfa_expiry_aware and mfa_expiry_aware > now:
        # Success: Clear MFA code, generate JWT
        user.mfa_code = None
        user.mfa_code_expiry = None
        db.session.commit()
        
        access_token = generate_jwt_token(user)
        
        log_security_event('INFO', f'User {username} successfully completed MFA and received JWT.', 'AUTH_SUCCESS')
        
        return jsonify({
            'message': 'MFA successful. JWT issued.',
            'access_token': access_token,
            'role': user.role
        }), 200
    
    # Failure: Log and respond
    log_security_event('WARNING', f'MFA verification failed for user {username}. Code mismatch or expired.', 'AUTH_FAILURE')
    return jsonify({'message': 'Invalid or expired OTP code.'}), 401

# --- Protected Routes (RBAC Test) ---

@app.route('/data/admin-report', methods=['GET'])
@token_required(roles=['admin'])
def get_admin_report():
    """Access control test: Requires 'admin' role."""
    return jsonify({
        'message': f'Admin Report Accessed Successfully by {g.current_user.username} (Role: {g.current_user.role}).',
        'data': [
            {'metric': 'Total Users', 'value': 1024}, 
            {'metric': 'New Incidents (Past 24h)', 'value': 3}
        ]
    })

@app.route('/data/finance-data', methods=['GET'])
@token_required(roles=['finance'])
def get_finance_data():
    """Access control test: Requires 'finance' role."""
    return jsonify({
        'message': f'Finance Data Accessed Successfully by {g.current_user.username} (Role: {g.current_user.role}).',
        'data': [
            {'metric': 'Q3 Revenue', 'value': '$12.5M'}, 
            {'metric': 'Budget Variance', 'value': '$-0.8M'}
        ]
    })

# --- Public Route (Intrusion Log Display) ---

@app.route('/data/log-anomaly', methods=['GET'])
def get_security_logs():
    """Retrieves the last 20 security logs for public viewing."""
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(20).all()
    
    log_list = [{
        'timestamp': log.timestamp.isoformat(),
        'level': log.level,
        'message': log.message,
        'source_ip': log.source_ip,
        'type': log.log_type
    } for log in logs]

    return jsonify(log_list), 200

# --- Local Debugging Startup (Optional, remove for deployment) ---

# if __name__ == '__main__':
#     # This block is ignored by Gunicorn in production
#     with app.app_context():
#         create_db_and_users()
#     print("\n--- Starting Flask Server on http://127.0.0.1:5000 ---")
#     app.run(debug=True)