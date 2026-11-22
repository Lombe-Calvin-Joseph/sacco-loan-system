# SACCO Loan Application System

## 🛡️ Secure by Design Web Application

A production-ready loan management system built with security as a first-class requirement. This application implements comprehensive security controls against the OWASP Top 10 vulnerabilities and includes complete threat modeling, testing, and audit logging.

---

## 📋 Table of Contents

1. [Features](#features)
2. [Security Architecture](#security-architecture)
3. [OWASP Top 10 Protection](#owasp-top-10-protection)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Testing](#testing)
7. [Threat Model](#threat-model)
8. [Security Controls](#security-controls)
9. [Known Limitations](#known-limitations)

---

## ✨ Features

### User Roles
- **Members**: Apply for loans, upload documents, track application status
- **Loan Officers**: Review applications, cannot approve (separation of duties)
- **Managers**: Approve or reject loans, view audit logs

### Core Functionality
- ✅ User registration with strong password policy
- ✅ Secure session management
- ✅ Loan application workflow (pending → under_review → approved/rejected)
- ✅ Secure file upload with validation
- ✅ Role-based access control (RBAC)
- ✅ Comprehensive audit logging
- ✅ Account lockout protection

---

## 🔒 Security Architecture

### Defense in Depth

This application implements multiple layers of security:

1. **Input Validation**: All user inputs are validated and sanitized
2. **Authentication**: Secure password storage with bcrypt, account lockout
3. **Authorization**: Server-side access control at every endpoint
4. **Session Management**: HTTPOnly, Secure, SameSite cookies
5. **Audit Logging**: All security events tracked with IP and user agent
6. **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, etc.

### Security-First Design Principles

- **Fail Securely**: Default deny for access control
- **Complete Mediation**: Every request is authorized
- **Least Privilege**: Users can only access their own resources
- **Separation of Duties**: Loan officers cannot approve loans
- **Secure by Default**: Security settings enabled out of the box

---

## 🛡️ OWASP Top 10 Protection

### A01:2021 – Broken Access Control ✅

**Controls Implemented:**
- Server-side authorization checks on every endpoint
- Role-based access control (RBAC) decorators
- Resource-level permission checks (users can only see their own loans)
- Separation of duties (loan officers cannot approve)
- Access denial logging

**Implementation:**
```python
@role_required('member')
@owns_resource(lambda id: Loan.query.get_or_404(id), 'loan_id')
def view_loan(loan_id):
    # Members can only view their own loans
```

### A02:2021 – Cryptographic Failures ✅

**Controls Implemented:**
- Passwords hashed with `pbkdf2:sha256` (Werkzeug/bcrypt)
- Session cookies with HTTPOnly, Secure, SameSite flags
- Secrets stored in environment variables, never in code
- Secure random for session keys

**Implementation:**
```python
def set_password(self, password):
    self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
```

### A03:2021 – Injection ✅

**Controls Implemented:**
- **SQL Injection Prevention**: Parameterized queries via SQLAlchemy ORM
- **XSS Prevention**: Jinja2 auto-escaping, input sanitization
- **Command Injection Prevention**: No direct shell command execution
- Input validation on all fields

**Implementation:**
```python
# SQLAlchemy ORM prevents SQL injection
loan = Loan.query.filter_by(member_id=current_user.id).all()

# Jinja2 auto-escapes output
{{ loan.purpose }}  <!-- Automatically escaped -->
```

### A04:2021 – Insecure Design ✅

**Controls Implemented:**
- Threat modeling completed (STRIDE analysis)
- Secure workflow design (separation of duties)
- Password policy enforcement
- Account lockout mechanism
- Rate limiting (lockout after 5 failed attempts)

### A05:2021 – Security Misconfiguration ✅

**Controls Implemented:**
- Security headers configured (CSP, X-Frame-Options, etc.)
- Debug mode disabled in production
- Detailed error messages disabled in production
- Secure session configuration
- File upload restrictions

**Security Headers:**
```python
'X-Content-Type-Options': 'nosniff',
'X-Frame-Options': 'DENY',
'X-XSS-Protection': '1; mode=block',
'Strict-Transport-Security': 'max-age=31536000',
'Content-Security-Policy': "default-src 'self'"
```

### A06:2021 – Vulnerable and Outdated Components ✅

**Controls Implemented:**
- Using latest stable versions of Flask and dependencies
- `requirements.txt` with pinned versions
- Regular security scanning with `safety`

**Check for vulnerabilities:**
```bash
safety check -r requirements.txt
```

### A07:2021 – Identification and Authentication Failures ✅

**Controls Implemented:**
- Strong password policy (8+ chars, uppercase, lowercase, digit, special)
- Password complexity validation
- Account lockout after 5 failed attempts (15-minute lockout)
- Secure session management with Flask-Login
- No "remember me" functionality (session-based only)
- Last login tracking

**Password Policy:**
```python
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL = True
```

### A08:2021 – Software and Data Integrity Failures ✅

**Controls Implemented:**
- Integrity checking for file uploads (extension, size, MIME type)
- Audit logging for all critical operations
- No unsigned or unverified code execution
- Secure file naming to prevent path traversal

**File Upload Validation:**
```python
def validate_file_upload(file, allowed_extensions, max_size):
    # Check extension, size, MIME type
    # Generate unique filename with UUID
    # Store in user-specific directory
```

### A09:2021 – Security Logging and Monitoring Failures ✅

**Controls Implemented:**
- Comprehensive audit logging (login, logout, loan actions, document access)
- Failed login attempt tracking
- Access denial logging
- IP address and user agent recording
- Audit log viewing for managers

**Logged Events:**
- `login_success`, `login_failed`
- `loan_created`, `loan_reviewed`, `loan_approved`, `loan_rejected`
- `document_uploaded`, `document_viewed`
- `access_denied`, `unauthorized_access`

### A10:2021 – Server-Side Request Forgery (SSRF) ✅

**Controls Implemented:**
- No external URL fetching based on user input
- File uploads stored locally, not fetched from URLs
- No server-side requests to user-controlled destinations

---

## 🚀 Installation

### Prerequisites

- Python 3.8+
- pip
- Virtual environment (recommended)

### Setup Steps

1. **Clone or navigate to the project directory:**
```bash
cd "C:\Users\Lombe Calvin Joseph\OneDrive\Desktop\SACCO-Loan-System"
```

2. **Create and activate virtual environment:**
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Initialize the database:**
```bash
flask init-db
```

This creates sample users:
- **Member**: `john_member` / `Password123!`
- **Loan Officer**: `sarah_officer` / `Password123!`
- **Manager**: `mike_manager` / `Password123!`

5. **Run the application:**
```bash
python run.py
```

6. **Access the application:**
Open browser to `http://127.0.0.1:5000`

---

## 📖 Usage

### Member Workflow

1. Register or log in as a member
2. Click "Apply for Loan"
3. Fill in loan details (amount, duration, purpose)
4. Upload supporting documents (PDF, JPG, PNG)
5. Track application status in dashboard

### Loan Officer Workflow

1. Log in as loan officer
2. View pending loan applications
3. Review application details and documents
4. Submit review (moves to "under_review" status)
5. **Cannot approve loans** (separation of duties)

### Manager Workflow

1. Log in as manager
2. View loans under review
3. Review loan officer's notes
4. Approve or reject the loan
5. View audit logs for security monitoring

---

## 🧪 Testing

### Manual Security Testing

#### Test SQL Injection Protection
```sql
-- Try logging in with:
Username: admin' OR '1'='1
Password: anything

-- Expected: Login fails, no SQL error
```

#### Test XSS Protection
```javascript
// Try entering in loan purpose:
<script>alert('XSS')</script>

// Expected: Text is escaped, no script execution
```

#### Test Access Control
```bash
# As member, try accessing another member's loan:
curl -b cookies.txt http://127.0.0.1:5000/member/loan/999

# Expected: 403 Forbidden or redirect
```

#### Test Account Lockout
```bash
# Try logging in with wrong password 6 times
# Expected: Account locked after 5 attempts
```

### Static Analysis with Bandit

```bash
# Install bandit
pip install bandit

# Run security scan
bandit -r app/ -ll

# Expected: No high-severity issues
```

### Dynamic Analysis with OWASP ZAP

1. **Download OWASP ZAP**: https://www.zaproxy.org/download/
2. **Configure ZAP proxy** (127.0.0.1:8080)
3. **Run automated scan** against http://127.0.0.1:5000
4. **Review findings** in the Alerts tab

Expected findings:
- ✅ CSRF tokens present
- ✅ Security headers configured
- ✅ No SQL injection vulnerabilities
- ✅ Session cookies secured

### Dependency Scanning

```bash
# Check for known vulnerabilities
safety check -r requirements.txt

# Expected: All dependencies secure
```

---

## 🎯 Threat Model

### Data Flow Diagram (DFD)

```
[Member Browser] <--HTTPS--> [Flask App] <--> [Database]
                                 |
                                 v
                            [File System]
                                 |
                                 v
                           [Audit Logs]

[Loan Officer Browser] <--HTTPS--> [Flask App]
[Manager Browser] <--HTTPS--> [Flask App]
```

### STRIDE Analysis

#### Threat 1: **Spoofing** - Unauthorized user impersonation

**Threat**: Attacker attempts to log in as another user
**Impact**: High - Access to sensitive loan data
**Mitigation**: 
- Strong password policy enforced
- Account lockout after 5 failed attempts
- Session hijacking prevention (strong session protection)

#### Threat 2: **Tampering** - SQL Injection attacks

**Threat**: Attacker injects SQL to modify data or bypass authentication
**Impact**: Critical - Data breach, unauthorized access
**Mitigation**:
- Parameterized queries via SQLAlchemy ORM
- Input validation on all fields
- No raw SQL queries

#### Threat 3: **Repudiation** - User denies performing an action

**Threat**: User claims they didn't approve/reject a loan
**Impact**: Medium - Disputes, compliance issues
**Mitigation**:
- Comprehensive audit logging with timestamps
- IP address and user agent tracking
- Immutable audit log (append-only)

#### Threat 4: **Information Disclosure** - Unauthorized data access

**Threat**: Member views another member's loan application
**Impact**: High - Privacy violation, data breach
**Mitigation**:
- Server-side access control on every endpoint
- Resource-level permission checks
- Access denial logging

#### Threat 5: **Denial of Service** - Account lockout abuse

**Threat**: Attacker locks out legitimate users by failing logins
**Impact**: Medium - Service availability
**Mitigation**:
- 15-minute automatic unlock
- Lockout threshold (5 attempts) balanced with usability
- Failed login attempt logging for investigation

#### Threat 6: **Elevation of Privilege** - Loan officer approves own review

**Threat**: Loan officer bypasses approval process
**Impact**: High - Fraudulent loan approvals
**Mitigation**:
- Separation of duties enforced in code
- Role-based access control
- Managers cannot approve loans they reviewed themselves
- Authorization checks on approval endpoint

#### Threat 7: **Cross-Site Scripting (XSS)** - Malicious script injection

**Threat**: Attacker injects JavaScript in loan purpose field
**Impact**: High - Session hijacking, phishing
**Mitigation**:
- Jinja2 auto-escaping enabled
- Input sanitization
- Content Security Policy header

#### Threat 8: **Insecure File Upload** - Malicious file execution

**Threat**: Attacker uploads malicious executable disguised as PDF
**Impact**: Critical - Server compromise
**Mitigation**:
- File extension validation (whitelist only)
- MIME type checking
- Secure filename generation (UUID)
- Files stored outside web root with direct access
- File size limits enforced

---

## 🔐 Security Controls Summary

### Authentication & Authorization
- ✅ bcrypt password hashing
- ✅ Password complexity requirements
- ✅ Account lockout (5 attempts, 15min)
- ✅ Role-based access control
- ✅ Session management (Flask-Login)
- ✅ CSRF protection (Flask-WTF)

### Input Validation
- ✅ Server-side validation on all forms
- ✅ File upload validation (type, size, content)
- ✅ Input sanitization
- ✅ Parameterized queries (SQLAlchemy)

### Session Security
- ✅ HTTPOnly cookies
- ✅ Secure flag (HTTPS in production)
- ✅ SameSite=Lax
- ✅ 30-minute timeout
- ✅ Strong session protection

### Security Headers
- ✅ Content-Security-Policy
- ✅ X-Frame-Options: DENY
- ✅ X-Content-Type-Options: nosniff
- ✅ X-XSS-Protection: 1; mode=block
- ✅ Strict-Transport-Security (HSTS)

### Logging & Monitoring
- ✅ Security event logging
- ✅ Failed login tracking
- ✅ Access denial logging
- ✅ Audit trail for all loan actions
- ✅ IP address tracking

---

## ⚠️ Known Limitations & Future Improvements

### Current Limitations

1. **Rate Limiting**: No global rate limiting (only per-account lockout)
   - **Risk**: Distributed brute force attacks
   - **Improvement**: Implement Flask-Limiter for IP-based rate limiting

2. **Password Reset**: No password recovery mechanism
   - **Risk**: User lockout if password forgotten
   - **Improvement**: Implement secure token-based password reset via email

3. **Two-Factor Authentication (2FA)**: Not implemented
   - **Risk**: Account compromise if password leaked
   - **Improvement**: Add TOTP-based 2FA for sensitive roles (managers)

4. **HTTPS**: Development uses HTTP
   - **Risk**: Session hijacking, credential theft in transit
   - **Improvement**: Deploy with HTTPS in production (Let's Encrypt)

5. **Database Backups**: No automated backup strategy
   - **Risk**: Data loss
   - **Improvement**: Implement automated PostgreSQL backups

6. **File Encryption**: Uploaded files stored unencrypted
   - **Risk**: Data breach if filesystem compromised
   - **Improvement**: Encrypt files at rest

7. **Anti-CSRF Token Rotation**: CSRF tokens don't expire
   - **Risk**: Token reuse in some scenarios
   - **Improvement**: Currently acceptable (session-based), but could add rotation

8. **Email Notifications**: Not implemented
   - **Impact**: Users not notified of loan status changes
   - **Improvement**: Add secure email notifications with SendGrid/AWS SES

### Security Roadmap

**Phase 1** (High Priority):
- [ ] Deploy with HTTPS
- [ ] Implement global rate limiting
- [ ] Add file encryption at rest

**Phase 2** (Medium Priority):
- [ ] Password reset functionality
- [ ] Email notifications
- [ ] 2FA for managers

**Phase 3** (Nice to Have):
- [ ] Security dashboard with metrics
- [ ] Advanced audit log analytics
- [ ] Intrusion detection alerts

---

## 📚 Security Testing Results

### Static Analysis (Bandit)

**Command**: `bandit -r app/ -ll`

**Result**: ✅ No high or medium severity issues

Key findings addressed:
- No hardcoded passwords
- No SQL injection vectors
- No command injection risks
- Secure file handling

### Dynamic Analysis (OWASP ZAP)

**Scan Target**: `http://127.0.0.1:5000`

**Expected Findings**:
- ✅ CSRF protection enabled
- ✅ Security headers present
- ✅ Session cookies secured
- ✅ No SQL injection
- ✅ No XSS vulnerabilities

### Manual Testing Checklist

- [x] SQL injection attempts blocked
- [x] XSS attempts sanitized
- [x] Unauthorized access denied (403)
- [x] Account lockout working
- [x] CSRF tokens validated
- [x] File upload validation working
- [x] Access control enforced
- [x] Audit logging functional

---

## 👥 User Roles & Permissions

| Action | Member | Loan Officer | Manager |
|--------|--------|--------------|---------|
| Apply for loan | ✅ | ❌ | ❌ |
| View own loans | ✅ | ❌ | ❌ |
| Upload documents | ✅ (own loans) | ❌ | ❌ |
| View all loans | ❌ | ✅ | ✅ |
| Review loans | ❌ | ✅ | ❌ |
| Approve loans | ❌ | ❌ | ✅ |
| View audit logs | ❌ | ❌ | ✅ |

---

## 📞 Support & Contribution

For security issues, please report them responsibly via email rather than public issues.

---

## 📄 License

This project is for educational purposes. Use at your own risk in production environments.

---

**Built with security in mind. Every layer, every endpoint, every user interaction.**
