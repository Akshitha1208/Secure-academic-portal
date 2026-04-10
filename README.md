# Secure Academic Portal

A full-stack secure project submission and verification system for academic workflows.

Students can upload project files, faculty can verify them with digital signatures, and admins can manage users and roles. The system demonstrates MFA, role-based access control, encryption, and integrity verification.

## Highlights

- Multi-step authentication:
  - Password authentication (SHA-256 + per-user salt)
  - OTP-based second factor (5-minute validity)
  - JWT-based session authorization
- Role-based access control (ACL) for `student`, `faculty`, and `admin`
- Secure file handling:
  - AES-256 (CBC) encryption for uploaded files
  - RSA-2048 OAEP encryption for AES key exchange
  - SHA-256 hash for integrity checks
- Faculty digital signatures:
  - RSA signatures on project hash
  - Signature verification endpoint for non-repudiation checks
- SQLite-backed persistence with structured schema

## Tech Stack

- Backend: Flask, Flask-CORS, PyJWT, PyCryptodome
- Frontend: HTML, CSS, Vanilla JavaScript
- Database: SQLite

## Project Structure

```text
secure-academic-portal/
|-- backend/
|   |-- app.py
|   |-- requirements.txt
|   |-- setup_test_data.py
|   |-- academic_portal.db
|   |-- database/
|   |   `-- db_manager.py
|   `-- security/
|       |-- auth.py
|       |-- acl.py
|       `-- crypto.py
|-- frontend/
|   |-- index.html
|   |-- app.js
|   `-- styles.css
|-- database/
|   `-- schema.sql
`-- README.md
```

## Local Setup

### 1. Clone and enter the project

```bash
git clone <your-repo-url>
cd secure-academic-portal
```

### 2. Set up backend dependencies

```bash
cd backend
python -m venv venv
```

Activate virtual environment:

- Windows:
  ```powershell
  .\venv\Scripts\activate
  ```
- macOS/Linux:
  ```bash
  source venv/bin/activate
  ```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 3. Initialize database and sample users

```bash
python setup_test_data.py
```

### 4. Run backend API

```bash
python app.py
```

Backend runs on: `http://localhost:5000`

### 5. Run frontend

Open a new terminal:

```bash
cd frontend
python -m http.server 8000
```

Frontend runs on: `http://localhost:8000`

## Demo Credentials


- Admin: `admin1` / `Admin@123`
- Faculty: `faculty1` / `Faculty@123`
- Student: `student1` / `Student@123`
- Student: `student2` / `Student@123`

## Core API Endpoints

### Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/verify-otp`
- `GET /api/profile`

### Projects

- `POST /api/projects/upload`
- `GET /api/projects`
- `GET /api/projects/<project_id>`
- `GET /api/projects/<project_id>/download`

### Verification

- `POST /api/projects/<project_id>/verify`
- `GET /api/verifications/<verification_id>/verify-signature`
- `GET /api/projects/<project_id>/verifications`

### Admin / System

- `GET /api/users`
- `PUT /api/users/<user_id>/role`
- `GET /api/system/acl`
- `GET /api/health`

## Security Design Notes

- Passwords are salted and hashed before storage.
- OTP is currently returned in the login response for demonstration; remove this in production and send via email/SMS.
- User private keys are stored in DB for demo simplicity; in production, store keys in a secure key management system (KMS/HSM) or encrypt at rest with strict controls.
- Flask app currently runs in `debug=True`; disable debug mode and use hardened deployment settings in production.

## Typical User Flow

1. User registers with a role.
2. User logs in with username/email + password.
3. User verifies OTP to receive JWT.
4. Student uploads project file (encrypted at rest).
5. Faculty verifies project and signs project hash.
6. Signature validity can be checked via verification endpoint.
7. Admin manages users and role assignments.

## Future Improvements

- Replace demo OTP flow with real email/SMS provider.
- Store secrets and keys in environment variables + secure vault.
- Add automated tests (unit + integration + security).
- Add rate limiting, audit logs, and brute-force protections.
- Containerize with Docker and add CI/CD pipeline.
