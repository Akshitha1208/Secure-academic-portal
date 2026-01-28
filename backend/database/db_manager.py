"""
Database Manager
Handles all database operations using SQLite

Tables:
1. users - User accounts with authentication data
2. projects - Student project submissions
3. verifications - Faculty verification records
4. otps - One-time passwords for MFA
"""

import sqlite3
import datetime
from pathlib import Path


class DatabaseManager:
    """Manages database operations"""
    
    def __init__(self, db_path='academic_portal.db'):
        self.db_path = db_path
        self.connection = None
    
    def get_connection(self):
        """Get database connection"""
        if self.connection is None:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
        return self.connection
    
    def init_db(self):
        """Initialize database with tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Projects table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                file_name TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                iv TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Verifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                faculty_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                comments TEXT,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (faculty_id) REFERENCES users(id)
            )
        ''')
        
        # OTPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp TEXT NOT NULL,
                expiry TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        print("Database initialized successfully")
    
    # ==================== USER OPERATIONS ====================
    
    def create_user(self, username, email, password_hash, salt, role, full_name, public_key, private_key):
        """Create a new user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, full_name, public_key, private_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, salt, role, full_name, public_key, private_key))
        
        conn.commit()
        return cursor.lastrowid
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        
        return dict(row) if row else None
    
    def get_user_by_username(self, username):
        """Get user by username"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        
        return dict(row) if row else None
    
    def get_user_by_email(self, email):
        """Get user by email"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        
        return dict(row) if row else None
    
    def get_all_users(self):
        """Get all users"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    def update_user_role(self, user_id, role):
        """Update user role"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET role = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (role, user_id))
        
        conn.commit()
    
    # ==================== PROJECT OPERATIONS ====================
    
    def create_project(self, user_id, title, description, file_name, encrypted_content, encrypted_key, iv, file_hash):
        """Create a new project"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO projects 
            (user_id, title, description, file_name, encrypted_content, encrypted_key, iv, file_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, title, description, file_name, encrypted_content, encrypted_key, iv, file_hash))
        
        conn.commit()
        return cursor.lastrowid
    
    def get_project_by_id(self, project_id):
        """Get project by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.username, u.full_name as student_name
            FROM projects p
            JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
        ''', (project_id,))
        
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_projects_by_user(self, user_id):
        """Get all projects by a specific user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.username
            FROM projects p
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id = ?
            ORDER BY p.created_at DESC
        ''', (user_id,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def get_all_projects(self):
        """Get all projects"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.username, u.full_name as student_name
            FROM projects p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        ''')
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def update_project_status(self, project_id, status):
        """Update project status"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE projects 
            SET status = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (status, project_id))
        
        conn.commit()
    
    # ==================== VERIFICATION OPERATIONS ====================
    
    def create_verification(self, project_id, faculty_id, status, comments, signature):
        """Create a verification record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO verifications 
            (project_id, faculty_id, status, comments, signature)
            VALUES (?, ?, ?, ?, ?)
        ''', (project_id, faculty_id, status, comments, signature))
        
        conn.commit()
        
        # Update project status
        self.update_project_status(project_id, status)
        
        return cursor.lastrowid
    
    def get_verification_by_id(self, verification_id):
        """Get verification by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT v.*, u.username as faculty_username, u.full_name as faculty_name
            FROM verifications v
            JOIN users u ON v.faculty_id = u.id
            WHERE v.id = ?
        ''', (verification_id,))
        
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_verifications_by_project(self, project_id):
        """Get all verifications for a project"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT v.*, u.username as faculty_username, u.full_name as faculty_name
            FROM verifications v
            JOIN users u ON v.faculty_id = u.id
            WHERE v.project_id = ?
            ORDER BY v.created_at DESC
        ''', (project_id,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def get_all_verifications(self):
        """Get all verifications"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT v.*, 
                   u.username as faculty_username, 
                   u.full_name as faculty_name,
                   p.title as project_title
            FROM verifications v
            JOIN users u ON v.faculty_id = u.id
            JOIN projects p ON v.project_id = p.id
            ORDER BY v.created_at DESC
        ''')
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    # ==================== OTP OPERATIONS ====================
    
    def store_otp(self, user_id, otp, expiry):
        """Store OTP for user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Clear old OTPs for this user
        cursor.execute('DELETE FROM otps WHERE user_id = ?', (user_id,))
        
        # Insert new OTP
        cursor.execute('''
            INSERT INTO otps (user_id, otp, expiry)
            VALUES (?, ?, ?)
        ''', (user_id, otp, expiry))
        
        conn.commit()
    
    def get_otp(self, user_id):
        """Get OTP for user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT otp, expiry 
            FROM otps 
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 1
        ''', (user_id,))
        
        row = cursor.fetchone()
        
        if row:
            return {
                'otp': row['otp'],
                'expiry': datetime.datetime.fromisoformat(row['expiry'])
            }
        return None
    
    def clear_otp(self, user_id):
        """Clear OTP for user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM otps WHERE user_id = ?', (user_id,))
        conn.commit()
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
