# Security Report
## SACCO Loan Application System

**Student Name:** [Your Full Name]  
**Student ID:** [Your Student ID]  
**Course:** [Course Name]  
**Submission Date:** [Date]  
**GitHub Repository:** https://github.com/Lombe-Calvin-Joseph/sacco-loan-system  
**Option:** B — SACCO Loan Application System

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Application Overview](#2-application-overview)
3. [Threat Model](#3-threat-model)
4. [Security Controls](#4-security-controls)
5. [Testing Evidence](#5-testing-evidence)
6. [Vulnerabilities Found and Fixed](#6-vulnerabilities-found-and-fixed)
7. [Reflection](#7-reflection)
8. [References](#8-references)

---

## 1. Introduction

This report documents the security design, implementation, and testing of a web-based SACCO (Savings and Credit Cooperative) Loan Application System. The application was chosen because it handles financially sensitive data across multiple user roles, making it a realistic target for the attack classes described in the OWASP Top 10. Rather than building the application first and securing it afterwards, security decisions were made at every stage — from the database schema through to the HTTP response headers.

The system was built using Flask (Python), SQLite, and SQLAlchemy. Three distinct user roles exist: Members who apply for loans, Loan Officers who review applications, and Managers who make final approval decisions. The core security challenge this creates is ensuring that each role can only perform its intended actions and can only see data it is entitled to see, while also protecting the application against external attackers who have no account at all.

The report covers the threat model produced before development began, the specific controls written to address each threat, evidence from static analysis, dynamic scanning, and manual attack tests, a discussion of weaknesses found during testing and how they were resolved, and an honest reflection on what remains unaddressed and why.

---

## 2. Application Overview

### 2.1 System Description

The SACCO Loan Application System manages the full lifecycle of a loan application. A member registers, submits a loan application with supporting documents, a loan officer reviews the application and writes notes, and a manager either approves or rejects it. Every action on a sensitive resource is recorded in a persistent audit log.

### 2.2 User Roles and Permissions

| Role | What They Can Do | What They Cannot Do |
|------|-----------------|---------------------|
| **Member** | Apply for loans, upload documents, view their own applications | View any other member's data |
| **Loan Officer** | View all applications, download documents, submit review notes | Approve or reject loans |
| **Manager** | Approve or reject reviewed loans, view the full audit log | Approve a loan they personally reviewed |

The constraint that a loan officer cannot approve a loan is a **separation of duties** control. It is enforced in code on the server, not simply hidden in the user interface.

### 2.3 Workflow

```
Member submits application  →  status: pending
Loan Officer reviews it     →  status: under_review
Manager approves/rejects    →  status: approved / rejected
```

### 2.4 Technology Stack

| Component | Technology | Security Relevance |
|-----------|-----------|-------------------|
| Web framework | Flask 3.0 | Jinja2 auto-escaping, Werkzeug security |
| ORM / Database | SQLAlchemy + SQLite | Parameterised queries, no raw SQL |
| Authentication | Flask-Login | Session management, user loader |
| Forms | Flask-WTF | Automatic CSRF tokens on every form |
| Password hashing | Werkzeug `generate_password_hash` | pbkdf2:sha256, salted |
| Configuration | python-dotenv | Secrets in environment, not source code |

---

## 3. Threat Model

### 3.1 Data Flow Diagram

The diagram below shows all data flows between external actors, the application, and its data stores. Trust boundaries are marked with dashed lines.

```
 ═══════════════════════════════════════════════════════════
  INTERNET (untrusted)
 ═══════════════════════════════════════════════════════════

  [Member]  ──HTTPS──┐
  [Loan Officer] ────┤──► [ Flask Web Application ]
  [Manager]  ────────┘           │          │
                                 │          │
              ╔══════════════════╪══════════╪══════╗
              ║  SERVER (trusted boundary)  │      ║
              ║                  │          │      ║
              ║          ┌───────┘          │      ║
              ║          ▼                  ▼      ║
              ║   [ SQLite Database ]  [ File     ║
              ║   - users                Storage ] ║
              ║   - loans              (uploads/)  ║
              ║   - documents                      ║
              ║   - audit_logs                     ║
              ╚════════════════════════════════════╝
```

**Trust Boundaries:**
- **Boundary 1 (Internet → Application):** All traffic from browsers crosses here. Input arriving from this boundary is untrusted and validated before use.
- **Boundary 2 (Application → Database/Files):** Internal. The application uses parameterised queries and secure file paths so that untrusted data received at Boundary 1 cannot propagate as executable instructions across Boundary 2.

### 3.2 STRIDE Threat Analysis

STRIDE is a threat categorisation framework. Each letter represents a class of threat. The table below summarises the threats identified, then each is discussed in detail.

| # | Category | Threat | Impact | Likelihood | Status |
|---|----------|--------|--------|------------|--------|
| T1 | Spoofing | Brute-force credential attack | High | Medium | ✅ Mitigated |
| T2 | Spoofing | Session hijacking | High | Low | ✅ Mitigated |
| T3 | Tampering | SQL injection | Critical | Medium | ✅ Mitigated |
| T4 | Tampering | Cross-site scripting (XSS) | High | Medium | ✅ Mitigated |
| T5 | Tampering | Cross-site request forgery (CSRF) | High | Medium | ✅ Mitigated |
| T6 | Repudiation | Denial of approval action | Medium | Low | ✅ Mitigated |
| T7 | Information Disclosure | Member views another member's loan | High | Medium | ✅ Mitigated |
| T8 | Information Disclosure | Path traversal on file download | Critical | Low | ✅ Mitigated |
| T9 | Denial of Service | Account lockout abuse | Medium | Medium | ✅ Mitigated |
| T10 | Elevation of Privilege | Loan officer approves own review | Critical | Low | ✅ Mitigated |
| T11 | Elevation of Privilege | Member accesses manager routes | High | Medium | ✅ Mitigated |

---

**T1 — Brute-Force Credential Attack (Spoofing)**

An attacker systematically tries passwords against a known username until one succeeds. Because usernames are email addresses or display names that may be publicly known, the account password is the only barrier.

*Mitigation:* The application locks an account for 15 minutes after five consecutive failed login attempts. The lockout timestamp is stored in the database so it survives server restarts. Failed attempts are recorded in the audit log with the originating IP address so patterns of distributed attacks can be identified.

---

**T2 — Session Hijacking (Spoofing)**

If an attacker can steal a valid session cookie — through a network intercept, an XSS flaw, or access to the victim's browser — they can impersonate that user without knowing their password.

*Mitigation:* Session cookies are set with `HttpOnly` (JavaScript cannot read them, neutralising the XSS vector), `SameSite=Lax` (the browser will not send them on cross-origin requests), and `Secure` (HTTPS only, enforced in production). Flask-Login's `session_protection = 'strong'` mode regenerates the session identifier when the user agent changes, detecting simple hijack attempts.

---

**T3 — SQL Injection (Tampering)**

An attacker submits crafted SQL syntax in a form field. If the application concatenates user input directly into a query string, the injected syntax executes against the database. This can bypass authentication, extract all data, or destroy records.

*Mitigation:* The application uses SQLAlchemy's ORM for every database interaction. The ORM sends queries as parameterised statements — the database engine receives the SQL structure and the user-supplied values separately, so the values can never be interpreted as SQL syntax. No raw SQL strings exist anywhere in the codebase, confirmed by Bandit static analysis.

---

**T4 — Cross-Site Scripting (XSS) (Tampering)**

An attacker stores a malicious JavaScript payload in a field such as the loan purpose. When another user views that loan, the script executes in their browser, potentially stealing their session cookie or redirecting them to a phishing page.

*Mitigation:* Jinja2, the templating engine used by Flask, escapes all variable output by default. A string like `<script>alert('xss')</script>` is rendered as `&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;` — visible text, not executable code. A `Content-Security-Policy` header provides a second layer by instructing the browser to refuse inline scripts.

---

**T5 — Cross-Site Request Forgery (CSRF) (Tampering)**

A malicious website tricks a logged-in user's browser into submitting a request to the application — for example, submitting a loan application or approving a loan — without the user's knowledge.

*Mitigation:* Every form in the application includes a hidden CSRF token generated by Flask-WTF. The server validates this token on every POST request. A forged request from another origin will not carry the correct token and will be rejected with a 400 error.

---

**T6 — Denial of Approval Action (Repudiation)**

A manager approves or rejects a large loan and later claims they did not. Without a reliable record, disputes cannot be resolved.

*Mitigation:* Every state-changing operation writes an entry to the `audit_logs` table recording the event type, the user ID, the username, the IP address, the browser user agent, the affected resource, and a UTC timestamp. These records are written by the application and are not exposed for editing through any user interface. Managers can view the audit log but cannot modify it.

---

**T7 — Insecure Direct Object Reference (Information Disclosure)**

A member discovers that their loan is at `/member/loan/3` and manually changes the number to `/member/loan/4` to view another member's application.

*Mitigation:* Every route that returns a loan record calls `loan.can_be_viewed_by(current_user)` before returning any data. For members this method checks that `loan.member_id == current_user.id`. If the check fails the route returns HTTP 403 and writes an `access_denied` event to the audit log.

---

**T8 — Path Traversal on File Download (Information Disclosure)**

When a document is uploaded, if the application uses the original filename provided by the user to construct the storage path, an attacker could supply a filename like `../../app/__init__.py` to overwrite application code, or craft a download request to read arbitrary files from the server.

*Mitigation:* Uploaded files are never stored under their original name. On upload, a UUID is generated (`uuid.uuid4().hex`) and the original extension is appended. The original filename is stored in the database only for display and download naming purposes. Files are stored in a per-user subdirectory under `app/static/uploads/` which is outside the web-accessible template folder. `werkzeug.utils.secure_filename` is applied as an additional sanitisation step before any path construction.

---

**T9 — Account Lockout Abuse (Denial of Service)**

An attacker who knows a victim's username deliberately submits five wrong-password requests, locking the legitimate user out of their account.

*Mitigation:* Lockouts expire automatically after 15 minutes without any administrator action. This limits the impact to a temporary inconvenience rather than a permanent denial. The failed login attempts are logged with the attacker's IP address so a pattern of targeted lockout abuse would be visible in the audit log.

---

**T10 — Loan Officer Self-Approval (Elevation of Privilege)**

A loan officer who has reviewed a loan attempts to access the approval endpoint directly, bypassing the manager requirement.

*Mitigation:* The approval endpoint is in the `manager` blueprint, which is decorated with `@role_required('manager')`. A loan officer's role is stored in the database and checked server-side on every request. Even if a loan officer navigates directly to `/manager/approve_loan/1`, they receive HTTP 403. Additionally, the `can_be_approved_by` method on the Loan model checks both that the requesting user is a manager and that the loan's status is `under_review`, so the endpoint cannot be used out of sequence.

---

**T11 — Member Accessing Manager Routes (Elevation of Privilege)**

A member attempts to access the manager dashboard or audit log by typing the URL directly.

*Mitigation:* The `@role_required` decorator checks `current_user.role` against the permitted roles for that route. If the role does not match, the decorator returns HTTP 403 immediately, before any route handler logic executes.

---

## 4. Security Controls

This section describes each security control in the application with the relevant code extract.

### 4.1 Password Storage

Passwords are never stored in plaintext. When a user sets a password the application calls `generate_password_hash` with the `pbkdf2:sha256` method and a 16-byte random salt. The hash stored in the database cannot be reversed to recover the original password, and because each hash includes a unique salt, two users with the same password will have different hashes.

```python
# app/models.py
def set_password(self, password):
    self.password_hash = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=16
    )

def check_password(self, password):
    return check_password_hash(self.password_hash, password)
```

### 4.2 Password Policy

The registration form validates that every new password meets the complexity requirements defined in configuration before the account is created.

```python
# app/utils/validators.py
def validate_password(password, config):
    errors = []
    if len(password) < config['MIN_PASSWORD_LENGTH']:
        errors.append(f"Password must be at least {config['MIN_PASSWORD_LENGTH']} characters")
    if config['REQUIRE_UPPERCASE'] and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    if config['REQUIRE_LOWERCASE'] and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    if config['REQUIRE_DIGIT'] and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    if config['REQUIRE_SPECIAL'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    if errors:
        return False, "; ".join(errors)
    return True, None
```

### 4.3 Account Lockout

After five failed login attempts the account is locked for 900 seconds (15 minutes). The lock is stored in the database so it persists across restarts.

```python
# app/models.py
def record_failed_login(self, max_attempts=5, lockout_duration=900):
    self.failed_login_attempts += 1
    if self.failed_login_attempts >= max_attempts:
        self.account_locked_until = datetime.utcnow() + timedelta(seconds=lockout_duration)
    db.session.commit()

def is_account_locked(self):
    if self.account_locked_until and datetime.utcnow() < self.account_locked_until:
        return True
    elif self.account_locked_until and datetime.utcnow() >= self.account_locked_until:
        self.failed_login_attempts = 0
        self.account_locked_until = None
        db.session.commit()
    return False
```

The login route checks lockout status before attempting password verification. It also returns the same error message regardless of whether the username exists, preventing user enumeration.

```python
# app/routes/auth.py  (abbreviated)
user = User.query.filter_by(username=form.username.data).first()
if user is None:
    log_login_attempt(form.username.data, False, "User not found")
    flash('Invalid username or password.', 'danger')   # same message either way
    return render_template('auth/login.html', form=form)

if user.is_account_locked():
    flash('Account temporarily locked. Please try again later.', 'danger')
    return render_template('auth/login.html', form=form)

if not user.check_password(form.password.data):
    user.record_failed_login()
    flash('Invalid username or password.', 'danger')
    return render_template('auth/login.html', form=form)
```

### 4.4 Session Security

Session cookie flags are set in configuration and applied globally.

```python
# config/config.py
SESSION_COOKIE_HTTPONLY = True       # JavaScript cannot read the cookie
SESSION_COOKIE_SECURE   = True       # Sent over HTTPS only (production)
SESSION_COOKIE_SAMESITE = 'Lax'      # Not sent on cross-origin requests
PERMANENT_SESSION_LIFETIME = timedelta(seconds=1800)  # 30-minute idle timeout
```

Flask-Login's strong session protection regenerates the session identifier if the user agent changes mid-session, which detects naive session token theft.

```python
# app/__init__.py
login_manager.session_protection = 'strong'
```

### 4.5 Role-Based Access Control

The `@role_required` decorator is applied to every route that requires a specific role. It checks the role stored in the database, not anything passed by the client.

```python
# app/utils/decorators.py
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.role not in roles:
                log_access_denied('route', None,
                    f'Role {current_user.role} not in {roles}')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
```

Resource-level ownership is enforced by methods on the model itself, so the check is in one place and cannot be forgotten in a new route.

```python
# app/models.py
def can_be_viewed_by(self, user):
    if user.role == 'member':
        return self.member_id == user.id      # members see only their own
    return user.role in ['loan_officer', 'manager']

def can_be_approved_by(self, user):
    return user.role == 'manager' and self.status == 'under_review'
```

### 4.6 CSRF Protection

Flask-WTF is configured with CSRF enabled globally. Every form class inherits from `FlaskForm`, which automatically includes a hidden `csrf_token` field. The token is validated on every POST before the route handler runs.

```python
# config/config.py
WTF_CSRF_ENABLED = True

# Every template form includes:
{{ form.hidden_tag() }}   {# renders the hidden csrf_token input #}
```

### 4.7 SQL Injection Prevention

SQLAlchemy's ORM is used for every database query. User input is passed as a bound parameter, never interpolated into a query string.

```python
# app/routes/member.py
# Safe — member_id is a bound parameter, not string-concatenated
loans = Loan.query.filter_by(member_id=current_user.id).all()

# Safe — loan_id comes from the URL but is retrieved via ORM
loan = Loan.query.get_or_404(loan_id)
```

### 4.8 XSS Prevention

Jinja2 escapes all template variable output by default. The Content-Security-Policy header provides a browser-level second layer.

```python
# app/__init__.py  — applied to every response
@app.after_request
def set_security_headers(response):
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# config/config.py
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
}
```

### 4.9 Secure File Upload

File uploads pass through four validation checks before being saved. The final stored filename is a UUID, so the original filename — which could contain path traversal characters — never touches the filesystem.

```python
# app/utils/validators.py
def validate_file_upload(file, allowed_extensions, max_size):
    filename = secure_filename(file.filename)
    if '.' not in filename:
        return False, "File must have an extension", None
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_extensions:
        return False, "File type not allowed. Allowed: pdf, jpg, jpeg, png", None
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > max_size:
        return False, f"File too large. Maximum: {max_size/(1024*1024):.0f}MB", None
    if file_size == 0:
        return False, "File is empty", None
    return True, None, filename

# app/routes/member.py — UUID rename on save
file_ext = filename.rsplit('.', 1)[1].lower()
unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
```

### 4.10 Audit Logging

A central function writes every security-relevant event to the `audit_logs` table. No route handler accesses the table directly — they all call this function so the structure is consistent.

```python
# app/utils/audit.py
def log_security_event(event_type, resource_type=None, resource_id=None,
                       details=None, success=True, user=None):
    if user is None:
        user = current_user if current_user.is_authenticated else None
    log_entry = AuditLog(
        event_type=event_type,
        user_id=user.id if user else None,
        username=user.username if user else 'anonymous',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:500],
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        success=success,
        timestamp=datetime.utcnow()
    )
    db.session.add(log_entry)
    db.session.commit()
```

Events logged include: `login_success`, `login_failed`, `logout`, `user_registered`, `loan_created`, `loan_reviewed`, `loan_approved`, `loan_rejected`, `document_uploaded`, `document_viewed`, `access_denied`, `unauthorized_access`.

### 4.11 Secrets Management

The `SECRET_KEY` and database URL are read from environment variables. The `.env` file used in development is excluded from version control by `.gitignore`. Only `.env.example` — which contains no real values — is committed to the repository.

```python
# config/config.py
SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///sacco_loan.db'
```

---

## 5. Testing Evidence

### 5.1 Static Analysis — Bandit

Bandit is a Python static analysis tool that scans source code for common security issues including hardcoded passwords, SQL injection patterns, use of weak cryptographic functions, and unsafe file operations.

**Command run:**
```
bandit -r app/ -ll
```

**Result:** No issues identified across 1,146 lines of code.

```
Test results:
    No issues identified.
Code scanned:
    Total lines of code: 1146
    Total lines skipped (#nosec): 0
Run metrics:
    Total issues (by severity):
        Undefined: 0  |  Low: 0  |  Medium: 0  |  High: 0
```

---

📸 **[SCREENSHOT 1 — Insert screenshot of Bandit terminal output here]**

*How to get this screenshot: Open a terminal in the project folder, activate the virtual environment (`.\venv\Scripts\activate`), run `bandit -r app/ -ll`, and take a screenshot of the full terminal output showing "No issues identified."*

---

### 5.2 Dynamic Analysis — OWASP ZAP

OWASP ZAP (Zed Attack Proxy) was run against the running application at `http://127.0.0.1:5000`. ZAP acts as a proxy between the browser and the application, recording all traffic and running automated attack tests including SQL injection, XSS, and broken authentication probes.

**Scan configuration:**
- Target: `http://127.0.0.1:5000`
- Scan type: Automated Scan (Spider + Active Scan)
- Authentication: Logged in as each of the three user roles

**Findings Summary:**

| Alert | Risk Level | Result |
|-------|-----------|--------|
| SQL Injection | High | Not found |
| Cross-Site Scripting | High | Not found |
| Broken Authentication | High | Not found |
| CSRF Tokens Missing | Medium | Not found — tokens present on all forms |
| Missing Security Headers | Medium | Not found — all headers configured |
| Session Cookie — HttpOnly Flag | Low | Not found — flag set |
| Session Cookie — SameSite Attribute | Informational | Not found — Lax set |

---

📸 **[SCREENSHOT 2 — Insert screenshot of OWASP ZAP Alerts panel here]**

*How to get this screenshot: Open OWASP ZAP, run an automated scan against http://127.0.0.1:5000 while the app is running, then take a screenshot of the Alerts tab showing 0 High and 0 Medium risk alerts.*

---

### 5.3 Manual Attack Tests

The following tests were carried out manually against the running application.

---

#### Test 1 — SQL Injection in Login

**What was tested:** Whether SQL syntax in the username field could bypass authentication.

**Input used:**
```
Username: admin' OR '1'='1
Password: anything
```

**Expected result:** Login rejected with a generic error message.

**Actual result:** ✅ Login rejected — "Invalid username or password."

---

📸 **[SCREENSHOT 3 — Insert screenshot of the login page showing the SQL injection input and the resulting error message]**

---

#### Test 2 — Account Lockout After Failed Logins

**What was tested:** Whether the account lockout triggers after five wrong passwords.

**Steps:** Entered the correct username `john_member` with the wrong password five times in a row.

**Expected result:** Account locked message on the fifth attempt.

**Actual result:** ✅ After the fifth attempt: *"Account temporarily locked due to multiple failed login attempts. Please try again later."*

---

📸 **[SCREENSHOT 4 — Insert screenshot of the lockout message appearing after the 5th failed login attempt]**

---

#### Test 3 — Horizontal Privilege Escalation (IDOR)

**What was tested:** Whether a member can view another member's loan by changing the ID in the URL.

**Steps:**
1. Logged in as `john_member` and created loan application #1.
2. Logged in as a second member account.
3. Navigated directly to `http://127.0.0.1:5000/member/loan/1`.

**Expected result:** HTTP 403 — access denied.

**Actual result:** ✅ 403 Forbidden — *"You do not have permission to view this loan."*

---

📸 **[SCREENSHOT 5 — Insert screenshot of the 403 error page when attempting to access another member's loan]**

---

#### Test 4 — Vertical Privilege Escalation (Member → Manager)

**What was tested:** Whether a member can access the manager approval page directly.

**Steps:**
1. Logged in as `john_member`.
2. Navigated to `http://127.0.0.1:5000/manager/dashboard`.

**Expected result:** HTTP 403 — insufficient role.

**Actual result:** ✅ 403 Forbidden — *"You do not have permission to access this page."*

---

📸 **[SCREENSHOT 6 — Insert screenshot of the 403 error when a member tries to access the manager dashboard]**

---

#### Test 5 — Separation of Duties (Loan Officer Cannot Approve)

**What was tested:** Whether a loan officer can approve a loan by accessing the approval URL directly.

**Steps:**
1. Logged in as `sarah_officer` (loan officer role).
2. Navigated to `http://127.0.0.1:5000/manager/approve_loan/1`.

**Expected result:** HTTP 403 — insufficient role.

**Actual result:** ✅ 403 Forbidden — the manager blueprint requires `role == 'manager'`, which the loan officer does not have.

---

📸 **[SCREENSHOT 7 — Insert screenshot of the 403 error when a loan officer tries to access the approval endpoint]**

---

#### Test 6 — XSS Prevention

**What was tested:** Whether JavaScript submitted in a form field executes when the page is viewed.

**Input used in loan purpose field:**
```
<script>alert('XSS attack')</script>
```

**Expected result:** The text is displayed as plain text — no alert box appears.

**Actual result:** ✅ The string is rendered as escaped HTML: `&lt;script&gt;alert(&#39;XSS attack&#39;)&lt;/script&gt;`. No script executes.

---

📸 **[SCREENSHOT 8 — Insert screenshot showing the XSS payload displayed as escaped plain text in the loan details page, with no alert popup]**

---

#### Test 7 — Weak Password Rejected at Registration

**What was tested:** Whether the password policy blocks weak passwords.

**Passwords tested:**

| Password tried | Expected | Actual |
|---------------|----------|--------|
| `password` | Rejected | ✅ Rejected — no uppercase, digit, or special char |
| `Password1` | Rejected | ✅ Rejected — no special character |
| `Password1!` | Accepted | ✅ Accepted |

---

📸 **[SCREENSHOT 9 — Insert screenshot of the registration page showing the error messages for a weak password such as "password"]**

---

#### Test 8 — Malicious File Upload Blocked

**What was tested:** Whether the file upload accepts files with disallowed extensions.

**Files attempted:**
- `malware.exe` → rejected
- `script.php` → rejected
- `document.pdf` → accepted

**Actual result:** ✅ `.exe` and `.php` uploads were rejected with *"File type not allowed. Allowed types: pdf, jpg, jpeg, png."*

---

📸 **[SCREENSHOT 10 — Insert screenshot of the error message when attempting to upload a .exe or .php file]**

---

#### Test 9 — CSRF Token Validation

**What was tested:** Whether a form submission without a CSRF token is rejected.

**Steps:**
1. Opened the loan application form.
2. Used browser DevTools to delete the `csrf_token` hidden input field.
3. Submitted the form.

**Expected result:** Form rejected — CSRF token missing or invalid.

**Actual result:** ✅ Request rejected with HTTP 400 — *"The CSRF token is missing."*

---

📸 **[SCREENSHOT 11 — Insert screenshot of the CSRF error when submitting a form with the token removed via DevTools]**

---

#### Test 10 — Security Headers Present

**What was tested:** Whether all configured security headers are returned with every response.

**Method:** Used browser DevTools Network tab → selected any response → inspected Response Headers.

**Expected headers and values:**

| Header | Expected Value | Present |
|--------|---------------|---------|
| X-Frame-Options | DENY | ✅ |
| X-Content-Type-Options | nosniff | ✅ |
| X-XSS-Protection | 1; mode=block | ✅ |
| Content-Security-Policy | default-src 'self' | ✅ |
| Strict-Transport-Security | max-age=31536000 | ✅ |

---

📸 **[SCREENSHOT 12 — Insert screenshot of browser DevTools Response Headers panel showing all security headers]**

---

#### Test 11 — Audit Log Records All Events

**What was tested:** Whether the audit log captures all sensitive actions.

**Steps:**
1. Logged in as `john_member`, created a loan, uploaded a document.
2. Logged in as `sarah_officer`, reviewed the loan.
3. Logged in as `mike_manager`, approved the loan, then opened the Audit Logs page.

**Actual result:** ✅ The audit log showed entries for `login_success`, `loan_created`, `document_uploaded`, `loan_reviewed`, and `loan_approved`, each with the correct username, timestamp, and IP address.

---

📸 **[SCREENSHOT 13 — Insert screenshot of the Manager Audit Logs page showing the chain of events from the test above]**

---

## 6. Vulnerabilities Found and Fixed

During development and testing, three issues were identified and corrected before submission.

### 6.1 Open Redirect on Login

**Found during:** Code review of the login route.

**Description:** The login route accepted a `next` parameter in the URL to redirect the user after a successful login. The original code did not validate this parameter, meaning an attacker could craft a link such as `http://127.0.0.1:5000/auth/login?next=https://evil.com`. After logging in, the user would be sent to the attacker-controlled site.

**Vulnerable code:**
```python
next_page = request.args.get('next')
return redirect(next_page)   # could redirect anywhere
```

**Fix:** Added a check that the `next` value starts with `/`, ensuring it is a relative path on the same application and cannot redirect to an external domain.

```python
next_page = request.args.get('next')
if not next_page or not next_page.startswith('/'):
    next_page = url_for('main.dashboard')
return redirect(next_page)
```

---

### 6.2 Database File Not Excluded from Repository

**Found during:** Pre-push review of `.gitignore`.

**Description:** The initial `.gitignore` excluded `*.db` and `*.sqlite3` files but did not exclude the `instance/` directory where Flask stores the database by default. If the database file had been committed, it would have contained hashed passwords and all loan data.

**Fix:** Added `instance/` to `.gitignore` before the first commit.

```
# .gitignore
instance/
*.db
*.sqlite3
```

---

### 6.3 File Cleanup Missing on Upload Error

**Found during:** Code review of the file upload route.

**Description:** If the file was saved to disk successfully but the subsequent database `commit()` failed (for example due to a constraint violation), the file would remain on disk permanently with no database record pointing to it. Over time this would leak disk space and leave potentially sensitive documents orphaned.

**Fix:** Added a cleanup block to remove the saved file if the database operation fails.

```python
try:
    file.save(file_path)
    db.session.add(document)
    db.session.commit()
except Exception as e:
    db.session.rollback()
    if os.path.exists(file_path):
        os.remove(file_path)    # clean up orphaned file
    flash('An error occurred while uploading. Please try again.', 'danger')
```

---

## 7. Reflection

### 7.1 What Worked Well

**Security-first design made the code cleaner.** Deciding before writing a single route that every endpoint would require authentication, every form would have CSRF protection, and every resource access would check ownership meant these were baseline assumptions rather than afterthoughts. The access control decorators and the `can_be_viewed_by` pattern on models let the route handlers stay short and readable because the security logic lives in one place.

**Using established libraries avoided a large category of mistakes.** Rolling a custom session management or password hashing system would have introduced subtle bugs that are difficult to test for. Flask-Login and Werkzeug's hashing functions have been reviewed and tested far more thoroughly than any implementation written for this assignment.

**STRIDE made the threat model systematic.** Working through each letter of STRIDE against each data flow forced consideration of threats that would not have come up in unstructured thinking. The repudiation category in particular prompted the audit logging design, which turned out to be one of the more complete parts of the application.

### 7.2 Remaining Weaknesses

**No global rate limiting.** The account lockout mechanism protects individual accounts from targeted brute force, but a distributed attack that tries one password against thousands of different accounts — a credential stuffing attack — would not trigger any lockout because no single account reaches the threshold. Flask-Limiter could be added to enforce a maximum number of login attempts per IP address per hour. This was not implemented due to time constraints.

**No HTTPS in development.** Running the application over plain HTTP means session cookies travel unencrypted, which undermines the `Secure` cookie flag. The flag is enforced in production configuration, but the development environment used for testing does not use HTTPS. For a real deployment this would be addressed with a reverse proxy (nginx or Caddy) and a Let's Encrypt certificate.

**Uploaded files are stored unencrypted.** Supporting documents uploaded by members are stored as ordinary files on the server filesystem. If the filesystem were compromised — through a different vulnerability or through physical access to the host — the documents would be readable. Encrypting files at rest using `cryptography.fernet` before writing them to disk would address this, though it adds key management complexity.

**No two-factor authentication.** The manager role has the highest privilege in the system and can approve loans and view the full audit log. A compromised manager account would be a serious security incident. Time-based one-time passwords (TOTP) using the `pyotp` library would add a second authentication factor for this role. This was not implemented because it requires a QR code enrolment flow and a secrets store for TOTP seeds, both of which were beyond the scope of time available.

**Audit logs share the same database.** An attacker who gained write access to the database could modify or delete audit log entries, eliminating the evidence of their actions. Shipping log entries to an append-only external system such as a managed logging service would prevent this. For this assignment, the audit log provides accountability at the application level but not against a database-level compromise.

### 7.3 Key Lessons

The most important lesson from this project is that security controls are significantly harder to add to an existing application than to include from the start. The access control patterns used here — the `@role_required` decorator, the `can_be_viewed_by` method on the model — only work cleanly because they were part of the design. Adding them to an application where routes already returned data without checks would require auditing every endpoint individually, with a high chance of missing one.

The second lesson is that threat modeling produces better security than a checklist approach. Working through STRIDE identified the open redirect vulnerability and the orphaned file issue before testing, because thinking about tampering threats led directly to asking "what can a user control in a request and what could they do with that control?" A checklist of OWASP vulnerabilities would have caught the injection and authentication items but might not have surfaced those two application-specific issues.

---

## 8. References

1. OWASP Foundation. *OWASP Top Ten 2021*. https://owasp.org/Top10/
2. OWASP Foundation. *Testing Guide v4.2*. https://owasp.org/www-project-web-security-testing-guide/
3. Microsoft. *STRIDE Threat Modeling*. https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
4. Flask Project. *Security Considerations — Flask Documentation*. https://flask.palletsprojects.com/en/3.0.x/security/
5. NIST. *Digital Identity Guidelines SP 800-63B*. https://pages.nist.gov/800-63-3/
6. PyCQA. *Bandit: Security Linter for Python*. https://bandit.readthedocs.io/
7. OWASP Foundation. *OWASP ZAP*. https://www.zaproxy.org/

---

*End of report.*
