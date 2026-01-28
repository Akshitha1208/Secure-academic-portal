"""
Test Data Setup Script
Creates sample users for testing all roles
"""

import sys
sys.path.append('.')

from security.auth import AuthManager
from security.crypto import CryptoManager
from database.db_manager import DatabaseManager

def setup_test_data():
    """Create sample users for testing"""
    
    print("=" * 70)
    print("SETTING UP TEST DATA")
    print("=" * 70)
    
    # Initialize managers
    db_manager = DatabaseManager()
    auth_manager = AuthManager(db_manager)
    crypto_manager = CryptoManager()
    
    # Initialize database
    print("\n1. Initializing database...")
    db_manager.init_db()
    print("   ✓ Database initialized")
    
    # Sample users
    test_users = [
        {
            'username': 'admin1',
            'email': 'admin@test.com',
            'password': 'Admin@123',
            'role': 'admin',
            'full_name': 'Admin User'
        },
        {
            'username': 'faculty1',
            'email': 'faculty@test.com',
            'password': 'Faculty@123',
            'role': 'faculty',
            'full_name': 'Dr. Faculty Member'
        },
        {
            'username': 'student1',
            'email': 'student@test.com',
            'password': 'Student@123',
            'role': 'student',
            'full_name': 'John Student'
        },
        {
            'username': 'student2',
            'email': 'student2@test.com',
            'password': 'Student@123',
            'role': 'student',
            'full_name': 'Jane Student'
        }
    ]
    
    print("\n2. Creating test users...")
    
    for user_data in test_users:
        # Check if user exists
        existing = db_manager.get_user_by_username(user_data['username'])
        if existing:
            print(f"   ⚠ User '{user_data['username']}' already exists, skipping...")
            continue
        
        # Hash password
        password_hash, salt = auth_manager.hash_password(user_data['password'])
        
        # Generate RSA keys
        private_key, public_key = crypto_manager.generate_rsa_keypair()
        
        # Create user
        user_id = db_manager.create_user(
            username=user_data['username'],
            email=user_data['email'],
            password_hash=password_hash,
            salt=salt,
            role=user_data['role'],
            full_name=user_data['full_name'],
            public_key=public_key,
            private_key=private_key
        )
        
        print(f"   ✓ Created {user_data['role']}: {user_data['username']} (ID: {user_id})")
    
    print("\n" + "=" * 70)
    print("TEST DATA SETUP COMPLETE")
    print("=" * 70)
    
    print("\n📝 TEST CREDENTIALS:")
    print("-" * 70)
    for user_data in test_users:
        print(f"\nRole: {user_data['role'].upper()}")
        print(f"Username: {user_data['username']}")
        print(f"Email: {user_data['email']}")
        print(f"Password: {user_data['password']}")
    
    print("\n" + "=" * 70)
    print("\n🚀 You can now:")
    print("1. Start the backend: python app.py")
    print("2. Start the frontend: python -m http.server 8000 (in frontend folder)")
    print("3. Access the application: http://localhost:8000")
    print("4. Login with any of the test credentials above")
    print("\n" + "=" * 70)

if __name__ == '__main__':
    setup_test_data()
