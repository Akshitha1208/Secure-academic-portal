-- ===================================================================
-- SECURE ACADEMIC PROJECT SUBMISSION & VERIFICATION PORTAL
-- DATABASE SCHEMA
-- ===================================================================

-- Database: academic_portal.db (SQLite)
-- This schema implements secure storage for:
-- 1. User authentication data (hashed passwords with salt)
-- 2. Encrypted project files
-- 3. Digital signatures for verification
-- 4. Multi-factor authentication OTPs

-- ===================================================================
-- TABLE: users
-- Purpose: Store user accounts with authentication credentials
-- Security: Passwords hashed with SHA-256 and unique salt
-- ===================================================================

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,         -- SHA-256 hashed password
    salt TEXT NOT NULL,                  -- Unique salt for each user
    role TEXT NOT NULL,                  -- student, faculty, admin
    full_name TEXT,
    public_key TEXT NOT NULL,            -- RSA-2048 public key (PEM format)
    private_key TEXT NOT NULL,           -- RSA-2048 private key (PEM format)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CHECK (role IN ('student', 'faculty', 'admin'))
);

-- Index for faster username/email lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- ===================================================================
-- TABLE: projects
-- Purpose: Store student project submissions with encrypted content
-- Security: Files encrypted with AES-256, keys encrypted with RSA
-- ===================================================================

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    file_name TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,     -- Base64-encoded AES-encrypted file
    encrypted_key TEXT NOT NULL,         -- Base64-encoded RSA-encrypted AES key
    iv TEXT NOT NULL,                    -- Base64-encoded initialization vector
    file_hash TEXT NOT NULL,             -- SHA-256 hash of original file
    status TEXT DEFAULT 'pending',       -- pending, verified, rejected
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (status IN ('pending', 'verified', 'rejected'))
);

-- Indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at);

-- ===================================================================
-- TABLE: verifications
-- Purpose: Store faculty verification records with digital signatures
-- Security: Digital signatures created using RSA private key
-- ===================================================================

CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    faculty_id INTEGER NOT NULL,
    status TEXT NOT NULL,                -- verified, rejected
    comments TEXT,
    signature TEXT NOT NULL,             -- Base64-encoded RSA digital signature
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (faculty_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (status IN ('verified', 'rejected'))
);

-- Indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_verifications_project_id ON verifications(project_id);
CREATE INDEX IF NOT EXISTS idx_verifications_faculty_id ON verifications(faculty_id);
CREATE INDEX IF NOT EXISTS idx_verifications_created_at ON verifications(created_at);

-- ===================================================================
-- TABLE: otps
-- Purpose: Store one-time passwords for multi-factor authentication
-- Security: Time-limited, single-use OTPs
-- ===================================================================

CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    otp TEXT NOT NULL,                   -- 6-digit OTP
    expiry TIMESTAMP NOT NULL,           -- OTP expiration time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for faster OTP lookups
CREATE INDEX IF NOT EXISTS idx_otps_user_id ON otps(user_id);
CREATE INDEX IF NOT EXISTS idx_otps_expiry ON otps(expiry);

-- ===================================================================
-- SAMPLE DATA FOR TESTING
-- ===================================================================

-- Note: These are sample users with pre-hashed passwords
-- Actual password hashing is done by the application
-- 
-- Sample credentials (for testing only):
-- Username: student1, Password: Student@123
-- Username: faculty1, Password: Faculty@123
-- Username: admin1, Password: Admin@123

-- ===================================================================
-- SECURITY NOTES
-- ===================================================================

-- 1. PASSWORD SECURITY:
--    - All passwords are hashed using SHA-256 with unique salts
--    - Salts are 256-bit (64 hex characters)
--    - No plaintext passwords are stored
--    - Constant-time comparison prevents timing attacks

-- 2. ENCRYPTION:
--    - Project files encrypted with AES-256 in CBC mode
--    - AES keys encrypted with RSA-2048 OAEP
--    - Base64 encoding for binary data storage
--    - Initialization vectors (IV) stored separately

-- 3. DIGITAL SIGNATURES:
--    - RSA-2048 signatures on SHA-256 hashes
--    - Provides non-repudiation and integrity
--    - Public key verification enables trust

-- 4. ACCESS CONTROL:
--    - Enforced at application layer via ACL
--    - Database constraints ensure data integrity
--    - Foreign key cascades maintain consistency

-- 5. MFA (Multi-Factor Authentication):
--    - Time-limited OTPs (5 minutes)
--    - Single-use tokens cleared after verification
--    - Separate authentication step

-- ===================================================================
-- END OF SCHEMA
-- ===================================================================
