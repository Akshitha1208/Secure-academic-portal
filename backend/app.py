"""
Secure Academic Project Submission & Verification Portal
Backend Application - Flask Implementation

Security Features Implemented:
1. Authentication (NIST SP 800-63-2 Compliant)
   - SHA-256/bcrypt password hashing with unique salts
   - Multi-Factor Authentication (MFA) with email OTP
2. Authorization - Access Control List (ACL)
3. Encryption - RSA key exchange + AES-256
4. Digital Signatures using RSA
5. Hashing with salt for passwords and file integrity
6. Base64 encoding for encrypted data
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from functools import wraps
import jwt
import datetime
import secrets
import hashlib
import base64
import os
from io import BytesIO

# Import our security modules
from security.auth import AuthManager
from security.crypto import CryptoManager
from security.acl import ACLManager
from database.db_manager import DatabaseManager

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['JWT_EXPIRATION_HOURS'] = 24

# Initialize managers
db_manager = DatabaseManager()
auth_manager = AuthManager(db_manager)
crypto_manager = CryptoManager()
acl_manager = ACLManager()

# ==================== HELPER FUNCTIONS ====================

def token_required(f):
    """Decorator to verify JWT tokens"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = db_manager.get_user_by_id(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def check_permission(subject_role, action, object_type):
    """Check if user has permission to perform action on object"""
    return acl_manager.check_permission(subject_role, action, object_type)

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """
    User registration endpoint
    Requires: username, email, password, role
    """
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'student')
        full_name = data.get('full_name', '')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate role
        if role not in ['student', 'faculty', 'admin']:
            return jsonify({'error': 'Invalid role'}), 400
        
        # Check if user exists
        if db_manager.get_user_by_username(username) or db_manager.get_user_by_email(email):
            return jsonify({'error': 'User already exists'}), 409
        
        # Hash password with salt
        password_hash, salt = auth_manager.hash_password(password)
        
        # Generate RSA key pair for user
        private_key, public_key = crypto_manager.generate_rsa_keypair()
        
        # Create user
        user_id = db_manager.create_user(
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            role=role,
            full_name=full_name,
            public_key=public_key,
            private_key=private_key  # In production, encrypt this!
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'username': username
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Single-factor authentication (Step 1 of MFA)
    Requires: username/email, password
    Returns: OTP sent to email
    """
    try:
        data = request.json
        identifier = data.get('identifier')  # username or email
        password = data.get('password')
        
        if not all([identifier, password]):
            return jsonify({'error': 'Missing credentials'}), 400
        
        # Get user by username or email
        user = db_manager.get_user_by_username(identifier)
        if not user:
            user = db_manager.get_user_by_email(identifier)
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password
        if not auth_manager.verify_password(password, user['password_hash'], user['salt']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate OTP
        otp = auth_manager.generate_otp()
        otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        
        # Store OTP in database
        db_manager.store_otp(user['id'], otp, otp_expiry)
        
        # In production, send OTP via email
        # For demonstration, return OTP (REMOVE IN PRODUCTION!)
        print(f"OTP for {user['username']}: {otp}")
        
        return jsonify({
            'message': 'OTP sent to your email',
            'user_id': user['id'],
            'otp': otp  # ONLY FOR DEMO - REMOVE IN PRODUCTION
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    """
    Multi-factor authentication (Step 2 of MFA)
    Requires: user_id, otp
    Returns: JWT token
    """
    try:
        data = request.json
        user_id = data.get('user_id')
        otp = data.get('otp')
        
        if not all([user_id, otp]):
            return jsonify({'error': 'Missing OTP or user_id'}), 400
        
        # Verify OTP
        if not auth_manager.verify_otp(user_id, otp):
            return jsonify({'error': 'Invalid or expired OTP'}), 401
        
        # Get user
        user = db_manager.get_user_by_id(user_id)
        
        # Generate JWT token
        token_payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        # Clear OTP
        db_manager.clear_otp(user_id)
        
        return jsonify({
            'message': 'Authentication successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'full_name': user['full_name']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== PROJECT MANAGEMENT ENDPOINTS ====================

@app.route('/api/projects/upload', methods=['POST'])
@token_required
def upload_project(current_user):
    """
    Upload project file (Student only)
    ACL: Student -> CREATE -> Projects
    Encrypts file with AES-256
    """
    try:
        # Check permission
        if not check_permission(current_user['role'], 'create', 'projects'):
            return jsonify({'error': 'Permission denied'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        title = request.form.get('title')
        description = request.form.get('description', '')
        
        if not title:
            return jsonify({'error': 'Title is required'}), 400
        
        # Read file content
        file_content = file.read()
        
        # Generate AES key for this file
        aes_key = crypto_manager.generate_aes_key()
        
        # Encrypt file content with AES
        encrypted_content, iv = crypto_manager.encrypt_aes(file_content, aes_key)
        
        # Encrypt AES key with user's public key (for demonstration)
        # In production, encrypt with a system public key
        encrypted_aes_key = crypto_manager.encrypt_rsa(aes_key, current_user['public_key'])
        
        # Calculate file hash for integrity
        file_hash = crypto_manager.calculate_hash(file_content)
        
        # Base64 encode encrypted data for storage
        encrypted_content_b64 = base64.b64encode(encrypted_content).decode('utf-8')
        encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        
        # Store in database
        project_id = db_manager.create_project(
            user_id=current_user['id'],
            title=title,
            description=description,
            file_name=file.filename,
            encrypted_content=encrypted_content_b64,
            encrypted_key=encrypted_key_b64,
            iv=iv_b64,
            file_hash=file_hash
        )
        
        return jsonify({
            'message': 'Project uploaded and encrypted successfully',
            'project_id': project_id,
            'file_hash': file_hash
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/projects', methods=['GET'])
@token_required
def get_projects(current_user):
    """
    Get projects based on role
    ACL: Student -> READ -> Own Projects
         Faculty -> READ -> All Projects
         Admin -> READ -> All Projects
    """
    try:
        if current_user['role'] == 'student':
            # Students can only see their own projects
            if not check_permission(current_user['role'], 'read', 'projects'):
                return jsonify({'error': 'Permission denied'}), 403
            projects = db_manager.get_projects_by_user(current_user['id'])
        else:
            # Faculty and Admin can see all projects
            if not check_permission(current_user['role'], 'read', 'projects'):
                return jsonify({'error': 'Permission denied'}), 403
            projects = db_manager.get_all_projects()
        
        return jsonify({'projects': projects}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/projects/<int:project_id>', methods=['GET'])
@token_required
def get_project(current_user, project_id):
    """
    Get specific project details
    """
    try:
        project = db_manager.get_project_by_id(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check permissions
        if current_user['role'] == 'student':
            if project['user_id'] != current_user['id']:
                return jsonify({'error': 'Permission denied'}), 403
        elif not check_permission(current_user['role'], 'read', 'projects'):
            return jsonify({'error': 'Permission denied'}), 403
        
        return jsonify({'project': project}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/projects/<int:project_id>/download', methods=['GET'])
@token_required
def download_project(current_user, project_id):
    """
    Download and decrypt project file
    """
    try:
        project = db_manager.get_project_by_id(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check permissions
        if current_user['role'] == 'student':
            if project['user_id'] != current_user['id']:
                return jsonify({'error': 'Permission denied'}), 403
        elif not check_permission(current_user['role'], 'read', 'projects'):
            return jsonify({'error': 'Permission denied'}), 403
        
        # Decode from base64
        encrypted_content = base64.b64decode(project['encrypted_content'])
        encrypted_key = base64.b64decode(project['encrypted_key'])
        iv = base64.b64decode(project['iv'])
        
        # Decrypt AES key with user's private key
        aes_key = crypto_manager.decrypt_rsa(encrypted_key, current_user['private_key'])
        
        # Decrypt file content
        decrypted_content = crypto_manager.decrypt_aes(encrypted_content, aes_key, iv)
        
        # Verify file integrity
        calculated_hash = crypto_manager.calculate_hash(decrypted_content)
        if calculated_hash != project['file_hash']:
            return jsonify({'error': 'File integrity check failed'}), 500
        
        # Return file
        return send_file(
            BytesIO(decrypted_content),
            as_attachment=True,
            download_name=project['file_name']
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== VERIFICATION & DIGITAL SIGNATURE ENDPOINTS ====================

@app.route('/api/projects/<int:project_id>/verify', methods=['POST'])
@token_required
def verify_project(current_user, project_id):
    """
    Verify and digitally sign a project (Faculty only)
    ACL: Faculty -> CREATE -> Verification Records
    Digital Signature: Hash(project) -> Encrypt with private key
    """
    try:
        # Check permission
        if not check_permission(current_user['role'], 'create', 'verification_records'):
            return jsonify({'error': 'Permission denied'}), 403
        
        data = request.json
        status = data.get('status', 'verified')
        comments = data.get('comments', '')
        
        project = db_manager.get_project_by_id(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Create digital signature
        # 1. Get project hash
        project_hash = project['file_hash']
        
        # 2. Sign hash with faculty's private key
        signature = crypto_manager.sign_data(
            project_hash.encode('utf-8'),
            current_user['private_key']
        )
        
        # 3. Base64 encode signature
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # Store verification record
        verification_id = db_manager.create_verification(
            project_id=project_id,
            faculty_id=current_user['id'],
            status=status,
            comments=comments,
            signature=signature_b64
        )
        
        return jsonify({
            'message': 'Project verified and signed successfully',
            'verification_id': verification_id,
            'signature': signature_b64
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verifications/<int:verification_id>/verify-signature', methods=['GET'])
@token_required
def verify_signature(current_user, verification_id):
    """
    Verify digital signature of a verification record
    Demonstrates non-repudiation and integrity
    """
    try:
        verification = db_manager.get_verification_by_id(verification_id)
        
        if not verification:
            return jsonify({'error': 'Verification not found'}), 404
        
        # Get project and faculty details
        project = db_manager.get_project_by_id(verification['project_id'])
        faculty = db_manager.get_user_by_id(verification['faculty_id'])
        
        # Decode signature
        signature = base64.b64decode(verification['signature'])
        
        # Verify signature
        is_valid = crypto_manager.verify_signature(
            project['file_hash'].encode('utf-8'),
            signature,
            faculty['public_key']
        )
        
        return jsonify({
            'verification_id': verification_id,
            'is_valid': is_valid,
            'faculty': faculty['full_name'],
            'verified_at': verification['created_at'],
            'project_hash': project['file_hash']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/projects/<int:project_id>/verifications', methods=['GET'])
@token_required
def get_project_verifications(current_user, project_id):
    """
    Get all verifications for a project
    """
    try:
        project = db_manager.get_project_by_id(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check permissions
        if current_user['role'] == 'student':
            if project['user_id'] != current_user['id']:
                return jsonify({'error': 'Permission denied'}), 403
        
        verifications = db_manager.get_verifications_by_project(project_id)
        
        return jsonify({'verifications': verifications}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== USER MANAGEMENT ENDPOINTS ====================

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    """
    Get all users (Admin only)
    ACL: Admin -> READ -> User Data
    """
    try:
        if not check_permission(current_user['role'], 'read', 'user_data'):
            return jsonify({'error': 'Permission denied'}), 403
        
        users = db_manager.get_all_users()
        
        # Remove sensitive data
        for user in users:
            user.pop('password_hash', None)
            user.pop('salt', None)
            user.pop('private_key', None)
        
        return jsonify({'users': users}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@token_required
def update_user_role(current_user, user_id):
    """
    Update user role (Admin only)
    ACL: Admin -> UPDATE -> User Data
    """
    try:
        if not check_permission(current_user['role'], 'update', 'user_data'):
            return jsonify({'error': 'Permission denied'}), 403
        
        data = request.json
        new_role = data.get('role')
        
        if new_role not in ['student', 'faculty', 'admin']:
            return jsonify({'error': 'Invalid role'}), 400
        
        db_manager.update_user_role(user_id, new_role)
        
        return jsonify({'message': 'User role updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get current user's profile"""
    try:
        user = dict(current_user)
        user.pop('password_hash', None)
        user.pop('salt', None)
        user.pop('private_key', None)
        
        return jsonify({'user': user}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== SYSTEM INFO ENDPOINTS ====================

@app.route('/api/system/acl', methods=['GET'])
@token_required
def get_acl_policy(current_user):
    """
    Get Access Control List policy
    Shows all permissions for demonstration
    """
    try:
        policy = acl_manager.get_policy()
        return jsonify({'acl_policy': policy}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Secure Academic Portal',
        'timestamp': datetime.datetime.utcnow().isoformat()
    }), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    # Initialize database
    db_manager.init_db()
    
    # Run application
    app.run(debug=True, host='0.0.0.0', port=5000)
