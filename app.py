import json
import os
import random
import string
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
# Set the environment variable for security, though not strictly required for this demo
os.environ['FLASK_SECRET_KEY'] = 'a_very_secret_key_for_jwt_signing'

class Config:
    """Application configuration settings."""
    SQLALCHEMY_DATABASE_URI = 'sqlite:///security_model.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'a_default_secret_key_if_env_not_set')
    JWT_EXPIRATION_MINUTES = 60
    
    # Intrusion Prevention Settings
    MAX_LOGIN_ATTEMPTS = 5 # Brute force prevention limit (per IP/user)
    RATE_LIMIT_WINDOW_SECONDS = 60 # Time window for rate limiting
    
    # Anomaly Detection Settings (Velocity Check)
    MAX_AUTHENTICATED_REQUESTS = 15 # Max requests per user in the anomaly window
    ANOMALY_CHECK_WINDOW_SECONDS = 30 # Time window for velocity checks
    
# Signature Blacklist (Simulating Known Attack Patterns for Signature-Based WAF)
KNOWN_MALICIOUS_SIGNATURES = [
    "SELECT * FROM users",
    "UNION ALL",
    "DROP TABLE",
    "<SCRIPT>",
    "CMD.EXE",
    "../",
    "1=1"
]

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# --- Database Models ---

class User(db.Model):
    """Represents an application user with auth and MFA details."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user') # Roles: admin, finance, user
    login_failures = db.Column(db.Integer, default=0) # For brute force counter
    mfa_code = db.Column(db.String(6), nullable=True)
    mfa_code_expiry = db.Column(db.DateTime(timezone=True), nullable=True) # Stored with timezone info

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SecurityLog(db.Model):
    """Records all security events for monitoring and audit trail."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    level = db.Column(db.String(10))  # INFO, WARNING, ALERT, CRITICAL
    event_type = db.Column(db.String(30)) # AUTH_SUCCESS, AUTH_FAILURE, RATE_LIMIT, AUTHZ_FAILURE, SIGNATURE_MATCH, VELOCITY_ANOMALY
    message = db.Column(db.Text)
    username = db.Column(db.String(80), nullable=True)
    source_ip = db.Column(db.String(50))
    path = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'event_type': self.event_type,
            'message': self.message,
            'username': self.username,
            'source_ip': self.source_ip,
            'path': self.path
        }

# --- Utility Functions ---

def log_security_event(level, event_type, message, username=None):
    """Helper function to log a security event."""
    # Get client IP address
    ip = get_client_ip()
    
    # Store the log in the database
    new_log = SecurityLog(
        level=level,
        event_type=event_type,
        message=message,
        username=username,
        source_ip=ip,
        path=request.path
    )
    db.session.add(new_log)
    # Commit is handled inside the decorator or route to ensure transactional integrity
    db.session.commit()

def get_client_ip():
    """Safely retrieves the client's IP address, accounting for proxies."""
    if request.headers.getlist("X-Forwarded-For"):
        # The true client IP is usually the first address in the list
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

# JWT and Authentication logic (Simplified, without external library)

def create_jwt(user_id, role, username):
    """Creates a simple, signed JWT containing user identity and role."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": user_id,
        "role": role,
        "username": username,
        # Expiration time is a timestamp for easy comparison
        "exp": (datetime.now(timezone.utc) + timedelta(minutes=app.config['JWT_EXPIRATION_MINUTES'])).timestamp()
    }
    # In a real app, this would be cryptographically signed. Here, we just base64 encode for demonstration.
    return json.dumps({"header": header, "payload": payload}) 

def decode_jwt(token):
    """Decodes and validates the simplified JWT."""
    try:
        data = json.loads(token)
        payload = data.get('payload')
        if not payload:
            return None
            
        # 1. Check expiration time (Offset-Aware comparison)
        now = datetime.now(timezone.utc).timestamp()
        if payload.get("exp") < now:
            return None # Token expired
            
        # 2. Return payload
        return payload
    except Exception:
        return None

# --- Security Decorators ---

def check_rate_limit(username=None):
    """Intrusion Prevention: Checks for brute force login attempts."""
    ip = get_client_ip()
    now = datetime.now(timezone.utc)
    time_window = now - timedelta(seconds=app.config['RATE_LIMIT_WINDOW_SECONDS'])

    # 1. Check IP-based brute force (any user)
    ip_failures = SecurityLog.query.filter(
        SecurityLog.source_ip == ip,
        SecurityLog.event_type == 'AUTH_FAILURE',
        SecurityLog.timestamp > time_window
    ).count()

    if ip_failures >= app.config['MAX_LOGIN_ATTEMPTS']:
        log_security_event('ALERT', 'RATE_LIMIT', f'IP rate limit hit: {ip_failures} failures.', username=username)
        return False, f"Too many login attempts from this IP address. Please wait {app.config['RATE_LIMIT_WINDOW_SECONDS']} seconds."

    # 2. Check Username-based lockout (specific user)
    if username:
        user_failures = SecurityLog.query.filter(
            SecurityLog.username == username,
            SecurityLog.event_type == 'AUTH_FAILURE',
            SecurityLog.timestamp > time_window
        ).count()
        
        if user_failures >= app.config['MAX_LOGIN_ATTEMPTS']:
            log_security_event('CRITICAL', 'ACCOUNT_LOCKOUT', f'Account lockout triggered for user: {username}', username=username)
            return False, f"Too many failed attempts for this account. Account temporarily locked. Please wait {app.config['RATE_LIMIT_WINDOW_SECONDS']} seconds."
            
    return True, None

def signature_and_anomaly_check(f):
    """
    Enhanced Intrusion Prevention: Combines Signature Detection (WAF-like) 
    and Velocity Anomaly Detection (User Behavior).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # We don't need the IP here, as it's primarily an RBAC/WAF/Velocity check.
        
        # --- 1. Signature-Based Detection (Web Application Firewall Model) ---
        
        # Get all request data (JSON body, form data, URL arguments)
        data_to_check = []
        
        # 1.1 Check JSON body
        try:
            if request.is_json:
                data_to_check.append(json.dumps(request.get_json()))
        except Exception:
            pass
        
        # 1.2 Check Form data
        if request.form:
            data_to_check.append(json.dumps(request.form.to_dict()))
            
        # 1.3 Check URL query parameters
        if request.args:
            data_to_check.append(json.dumps(request.args.to_dict()))

        all_data = " ".join(data_to_check).upper()

        for signature in KNOWN_MALICIOUS_SIGNATURES:
            if signature.upper() in all_data:
                # Attack detected! Block immediately.
                log_security_event('CRITICAL', 'SIGNATURE_MATCH', 
                                   f'Blocked request containing malicious signature: "{signature}"', 
                                   username=getattr(request, 'current_user', {}).get('username'))
                return jsonify({'message': 'Access Denied: Malicious signature detected (Signature-Based Prevention).'}), 403

        # --- 2. Velocity Anomaly Detection (Post-Authentication Check) ---
        
        # This check is only relevant if the user token was successfully decoded (i.e., post-login)
        current_user = getattr(request, 'current_user', None)
        if current_user:
            username = current_user.get('username')
            now = datetime.now(timezone.utc)
            time_window_start = now - timedelta(seconds=app.config['ANOMALY_CHECK_WINDOW_SECONDS'])

            # Query the log for the authenticated user's requests within the window
            recent_requests = SecurityLog.query.filter(
                SecurityLog.username == username,
                # Include successful log events that track legitimate activity
                SecurityLog.event_type.in_(['AUTH_SUCCESS', 'AUTHZ_SUCCESS']),
                SecurityLog.timestamp > time_window_start
            ).count()

            if recent_requests >= app.config['MAX_AUTHENTICATED_REQUESTS']:
                # Anomaly detected! Block access to prevent data exfiltration.
                log_security_event('ALERT', 'VELOCITY_ANOMALY', 
                                   f'User {username} triggered velocity anomaly: {recent_requests} requests in {app.config["ANOMALY_CHECK_WINDOW_SECONDS"]}s.', 
                                   username=username)
                return jsonify({'message': 'Access Denied: Detected abnormal request velocity (Anomaly-Based Prevention).'}), 403
                
            # Log the successful request that passed all checks for the anomaly calculation
            # This request itself must be logged so it counts towards the next velocity check
            log_security_event('INFO', 'AUTHZ_SUCCESS', f'Authenticated request accepted for user {username}.', username=username)


        # If all checks pass, proceed to the original function
        return f(*args, **kwargs)
    return decorated


def token_required(roles=None):
    """
    Wrapper for all protected routes:
    1. Decodes and validates JWT.
    2. Performs Role-Based Access Control (RBAC).
    """
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token or not token.startswith('Bearer '):
                return jsonify({'message': 'Authentication required. Token missing or invalid format.'}), 401

            token = token.split(' ')[1]
            current_user = decode_jwt(token)
            
            if not current_user:
                return jsonify({'message': 'Authentication failed. Token invalid or expired.'}), 401

            # Attach user info to the request object for use by other checks/routes (like anomaly check)
            request.current_user = current_user
            
            # --- 3. Role-Based Access Control (Authorization) ---
            if roles and current_user.get('role') not in roles:
                log_security_event('CRITICAL', 'AUTHZ_FAILURE', 
                                   f'User {current_user.get("username")} (Role: {current_user.get("role")}) attempted unauthorized access to {request.path}.', 
                                   username=current_user.get('username'))
                return jsonify({'message': 'Authorization Failed: Insufficient role permissions (RBAC).'}), 403
            
            return f(*args, **kwargs)
        return decorated
    return wrapper

# --- Initialization ---

with app.app_context():
    db.create_all()

    # Create dummy admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('adminpass123')
        db.session.add(admin)
        
    # Create dummy finance user if not exists
    if not User.query.filter_by(username='finance').first():
        finance = User(username='finance', role='finance')
        finance.set_password('financepass')
        db.session.add(finance)
        
    # Create dummy standard user if not exists
    if not User.query.filter_by(username='user1').first():
        user1 = User(username='user1', role='user')
        user1.set_password('userpass')
        db.session.add(user1)
        
    db.session.commit()
    print("Database initialized and dummy users created: admin, finance, user1.")

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    """Application welcome message and instructions."""
    return jsonify({
        "message": "Welcome to the Enhanced Intrusion Prevention Model Demo Backend.",
        "endpoints": [
            "/register", "/login", "/verify-mfa",
            "/data/user-profile (user+)",
            "/data/finance-report (finance+)",
            "/data/admin-report (admin only)",
            "/data/high-value-asset (anomaly check)",
            "/data/log-anomaly (view logs)"
        ]
    })


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user') # Default role is 'user'

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists.'}), 409

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    log_security_event('INFO', 'ACCOUNT_CREATION', f'New user registered: {username} with role {role}.')
    
    return jsonify({'message': 'User registered successfully. You can now login.'}), 201


@app.route('/login', methods=['POST'])
def login():
    """Step 1: Authenticate password and generate MFA code."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required.'}), 400

    # --- Intrusion Prevention (Rate Limit) Check ---
    is_safe, reason = check_rate_limit(username)
    if not is_safe:
        return jsonify({'message': reason}), 429

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Successful password authentication
        
        # 1. Generate and store a temporary MFA code
        otp_code = ''.join(random.choices(string.digits, k=6))
        
        # 2. Set expiry time (5 minutes from now), ensuring it is timezone-aware (UTC)
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        user.mfa_code = otp_code
        user.mfa_code_expiry = expiry_time
        user.login_failures = 0 # Reset failures on success
        
        db.session.commit()
        log_security_event('INFO', 'AUTH_PASSWORD_SUCCESS', f'Password successful, MFA code generated for {username}.')
        
        # NOTE: In a real app, the OTP would be sent via email/SMS.
        return jsonify({
            'message': 'Password successful. Please verify with the MFA code.',
            'test_mfa_code': otp_code # DANGER: Only for demo/testing!
        }), 200
    else:
        # Failed password authentication
        message = f'Failed password attempt for user: {username}'
        log_security_event('WARNING', 'AUTH_FAILURE', message, username=username)
        return jsonify({'message': 'Invalid username or password.'}), 401


@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    """Step 2: Verify MFA code and issue JWT."""
    data = request.get_json()
    username = data.get('username')
    otp_code = data.get('mfa_code')
    
    if not username or not otp_code:
        return jsonify({'message': 'Username and MFA code required.'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        log_security_event('WARNING', 'AUTH_MFA_FAILURE', f'MFA attempt on non-existent user: {username}')
        return jsonify({'message': 'Invalid verification attempt.'}), 401

    now = datetime.now(timezone.utc)

    # Convert potentially naive datetime objects from SQLite to timezone-aware UTC for comparison
    user_expiry = user.mfa_code_expiry
    if user_expiry and user_expiry.tzinfo is None:
        user_expiry = user_expiry.replace(tzinfo=timezone.utc)

    # Check MFA code and expiry
    if user.mfa_code == otp_code and user_expiry and user_expiry > now:
        # Success: Clear MFA code, generate JWT
        user.mfa_code = None
        user.mfa_code_expiry = None
        
        token = create_jwt(user.id, user.role, user.username)
        
        db.session.commit()
        log_security_event('INFO', 'AUTH_SUCCESS', f'MFA successful, JWT issued for {username} (Role: {user.role}).', username=user.username)
        
        return jsonify({
            'message': 'Login successful. JWT token issued.',
            'token': f'Bearer {token}'
        }), 200
    else:
        # Failed verification
        reason = "Invalid MFA code" if user.mfa_code != otp_code else "MFA code expired"
        log_security_event('WARNING', 'AUTH_MFA_FAILURE', f'MFA attempt failed for {username}. Reason: {reason}.', username=user.username)
        return jsonify({'message': 'Invalid or expired MFA code.'}), 401

# --- Protected Data Routes ---

# The order of decorators is CRUCIAL: 
# 1. signature_and_anomaly_check (WAF/Velocity check first, before decoding token)
# 2. token_required (Authentication & RBAC)

@app.route('/data/user-profile', methods=['GET'])
@signature_and_anomaly_check
@token_required(roles=['user', 'finance', 'admin'])
def user_profile():
    """Accessible by all authenticated users."""
    user = request.current_user
    return jsonify({
        'message': f"Welcome, {user.get('username')}. Access granted to basic user profile data.",
        'user_id': user.get('user_id'),
        'role': user.get('role')
    })

@app.route('/data/finance-report', methods=['GET'])
@signature_and_anomaly_check
@token_required(roles=['finance', 'admin'])
def finance_report():
    """Accessible by finance and admin roles (Least Privilege Principle)."""
    user = request.current_user
    return jsonify({
        'message': f"ACCESS GRANTED: Financial Summary Q4. User: {user.get('username')}.",
        'report_data': {'revenue': 1200000, 'profit': 350000}
    })

@app.route('/data/admin-report', methods=['POST'])
@signature_and_anomaly_check
@token_required(roles=['admin'])
def admin_report():
    """Accessible by admin role only (Strict RBAC). Also used for Signature Test."""
    user = request.current_user
    data = request.get_json()
    action = data.get('action', 'unspecified')
    return jsonify({
        'message': f"CRITICAL ACCESS GRANTED: System Configuration Report. User: {user.get('username')}.",
        'action_taken': f"Admin action processed: {action}"
    })

@app.route('/data/high-value-asset', methods=['GET'])
@signature_and_anomaly_check
@token_required(roles=['admin', 'finance'])
def high_value_asset():
    """
    Simulates access to a highly sensitive asset.
    Will trigger the VELOCITY_ANOMALY alert if accessed too frequently.
    """
    user = request.current_user
    # The AUTHZ_SUCCESS logging happens inside the decorator for this route.
    return jsonify({
        'message': f"SENSITIVE DATA ACCESS GRANTED: High-Value Customer PII. User: {user.get('username')}.",
        'asset_id': 'HVAC-4456',
        'risk_level': 'High'
    })


@app.route('/data/log-anomaly', methods=['GET'])
@token_required(roles=['admin'])
def view_anomaly_logs():
    """
    Allows admins to view all security logs, particularly ANOMALY events.
    """
    # Filter for the most critical events for demonstration purposes
    logs = SecurityLog.query.filter(
        SecurityLog.level.in_(['ALERT', 'CRITICAL'])
    ).order_by(SecurityLog.timestamp.desc()).limit(50).all()
    
    return jsonify({
        'message': 'Displaying last 50 ALERT/CRITICAL logs (Anomaly Detection Feed)',
        'logs': [log.to_dict() for log in logs]
    })


if __name__ == '__main__':
    # Log level for SQLAlchemy to Debug (optional, but helpful)
    import logging
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
    app.run(debug=True)