"""
Authentication Manager
Implements NIST SP 800-63-2 Compliant Authentication

Features:
1. Password hashing with SHA-256 and unique salt
2. OTP generation and verification
3. Secure password verification
"""

import hashlib
import secrets
import datetime


class AuthManager:
    """Handles user authentication and MFA"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.otp_length = 6
        self.otp_validity_minutes = 5
    
    def hash_password(self, password):
        """
        Hash password using SHA-256 with unique salt
        
        Args:
            password (str): Plain text password
            
        Returns:
            tuple: (password_hash, salt)
        """
        # Generate unique salt (32 bytes = 256 bits)
        salt = secrets.token_hex(32)
        
        # Combine password and salt
        salted_password = password + salt
        
        # Hash using SHA-256
        password_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        
        return password_hash, salt
    
    def verify_password(self, password, stored_hash, salt):
        """
        Verify password against stored hash
        
        Args:
            password (str): Password to verify
            stored_hash (str): Stored password hash
            salt (str): Salt used in hashing
            
        Returns:
            bool: True if password is correct
        """
        # Hash the provided password with the stored salt
        salted_password = password + salt
        password_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        return secrets.compare_digest(password_hash, stored_hash)
    
    def generate_otp(self):
        """
        Generate a random 6-digit OTP
        
        Returns:
            str: 6-digit OTP
        """
        # Generate cryptographically secure random OTP
        otp = ''.join([str(secrets.randbelow(10)) for _ in range(self.otp_length)])
        return otp
    
    def verify_otp(self, user_id, provided_otp):
        """
        Verify OTP for a user
        
        Args:
            user_id (int): User ID
            provided_otp (str): OTP provided by user
            
        Returns:
            bool: True if OTP is valid and not expired
        """
        stored_otp_data = self.db_manager.get_otp(user_id)
        
        if not stored_otp_data:
            return False
        
        stored_otp = stored_otp_data['otp']
        expiry = stored_otp_data['expiry']
        
        # Check if OTP has expired
        if datetime.datetime.utcnow() > expiry:
            self.db_manager.clear_otp(user_id)
            return False
        
        # Constant-time comparison
        is_valid = secrets.compare_digest(provided_otp, stored_otp)
        
        return is_valid
    
    def send_otp_email(self, email, otp):
        """
        Send OTP via email (SMTP simulation)
        
        In production, implement actual SMTP email sending
        For demonstration, we'll just print the OTP
        
        Args:
            email (str): Recipient email
            otp (str): OTP to send
        """
        # Production implementation would use SMTP
        # Example with smtplib:
        # 
        # import smtplib
        # from email.mime.text import MIMEText
        # 
        # msg = MIMEText(f"Your OTP is: {otp}")
        # msg['Subject'] = 'Your Login OTP'
        # msg['From'] = 'noreply@academicportal.com'
        # msg['To'] = email
        # 
        # with smtplib.SMTP('smtp.gmail.com', 587) as server:
        #     server.starttls()
        #     server.login('your_email@gmail.com', 'your_password')
        #     server.send_message(msg)
        
        print(f"[EMAIL SIMULATION] Sending OTP to {email}: {otp}")
        print(f"OTP valid for {self.otp_validity_minutes} minutes")
