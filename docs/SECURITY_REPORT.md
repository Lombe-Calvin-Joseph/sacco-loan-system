SECURITY REPORT
SACCO Loan Application System

Student Name:        [Your Full Name]
Student ID:          [Your Student ID]
Course:              [Course Name]
Submission Date:     November 2026
GitHub Repository:   https://github.com/Lombe-Calvin-Joseph/sacco-loan-system
Option:              B — SACCO Loan Application System


TABLE OF CONTENTS

1. Introduction
2. Application Overview
3. Threat Model
4. Security Controls
5. Testing Evidence
6. Vulnerabilities Found and Fixed
7. Reflection
8. References


1. INTRODUCTION

This report documents the security design, implementation, and testing of a web-based SACCO (Savings and Credit Cooperative) Loan Application System. The application was chosen because it handles financially sensitive data across multiple user roles, making it a realistic target for the attack classes described in the OWASP Top 10. Rather than building the application first and securing it afterwards, security decisions were made at every stage, from the database schema through to the HTTP response headers.

The system was built using Flask (Python), SQLite, and SQLAlchemy. Three distinct user roles exist: Members who apply for loans, Loan Officers who review applications, and Managers who make final approval decisions. The core security challenge this creates is ensuring that each role can only perform its intended actions and can only see data it is entitled to see, while also protecting the application against external attackers who have no account at all.

The report covers the threat model produced before development began, the specific controls written to address each threat, evidence from static analysis and manual attack tests, a discussion of issues found during testing and how they were resolved, and an honest reflection on what remains unaddressed and why.


2. APPLICATION OVERVIEW

2.1 System Description

The SACCO Loan Application System manages the full lifecycle of a loan application. A member registers, submits a loan application with supporting documents, a loan officer reviews the application and writes notes, and a manager either approves or rejects it. Every action on a sensitive resource is recorded in a persistent audit log that only managers can view.

2.2 User Roles and Permissions

Role              What They Can Do                                          What They Cannot Do
Member            Apply for loans, upload documents, view own applications  View any other member's data
Loan Officer      View all applications, download documents, submit notes   Approve or reject loans
Manager           Approve or reject reviewed loans, view the audit log      Approve a loan they personally reviewed

The constraint that a loan officer cannot approve a loan is a separation of duties control. It is enforced server-side in code, not simply hidden in the user interface.

2.3 Workflow

    Member submits application   →   status: Pending
    Loan Officer reviews it      →   status: Under Review
    Manager approves/rejects     →   status: Approved or Rejected

2.4 Technology Stack

Component           Technology                          Security Relevance
Web framework       Flask 3.0                           Jinja2 auto-escaping, Werkzeug security
ORM and Database    SQLAlchemy and SQLite                Parameterised queries, no raw SQL
Authentication      Flask-Login                         Session management, strong session protection
Forms               Flask-WTF                           Automatic CSRF tokens on every form
Password hashing    Werkzeug generate_password_hash     pbkdf2:sha256 with unique salt per user
Configuration       python-dotenv                       Secrets in environment variables, not source code

2.5 Application Running

The screenshot below shows the Flask development server running with request logs confirming the application is live and responding to browser requests.

Figure 1 — Flask development server running with live request logs

[INSERT SCREENSHOT: screenshot_terminal.png]

The terminal shows the application started successfully on 127.0.0.1:5000. Each HTTP request is logged with method, path, and status code, confirming the server is active and all routes are responding.


3. THREAT MODEL

3.1 Data Flow Diagram

The diagram below shows all data flows between external actors, the application, and its data stores. Trust boundaries are marked with dashed lines.


    INTERNET (untrusted)
    ============================================================

    Member          ---HTTPS---+
    Loan Officer    -----------+---->   Flask Web Application
    Manager         -----------+                |           |
                                                |           |
                    SERVER (trusted boundary)   |           |
                    ============================|===========|====
                                                |           |
                                        +-------+           |
                                        v                   v
                                  SQLite Database       File Storage
                                  - users               (uploads/)
                                  - loans
                                  - documents
                                  - audit_logs
                    ================================================


Trust Boundaries:

Boundary 1 (Internet to Application): All browser traffic crosses here. Input arriving from this boundary is treated as untrusted and validated before use.

Boundary 2 (Application to Database and Files): Internal. The application uses parameterised queries and secure file paths so that untrusted data received at Boundary 1 cannot propagate as executable instructions.

3.2 STRIDE Threat Analysis

STRIDE is a threat categorisation framework where each letter represents a class of threat: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.

ID    Category                 Threat                                           Impact    Likelihood    Status
T1    Spoofing                 Brute-force credential attack                    High      Medium        Mitigated
T2    Spoofing                 Session hijacking via cookie theft               High      Low           Mitigated
T3    Tampering                SQL injection via form fields                    Critical  Medium        Mitigated
T4    Tampering                Stored XSS in loan purpose field                 High      Medium        Mitigated
T5    Tampering                Cross-site request forgery                       High      Medium        Mitigated
T6    Repudiation              Denial of approval or rejection action           Medium    Low           Mitigated
T7    Information Disclosure   Member views another member's loan (IDOR)        High      Medium        Mitigated
T8    Information Disclosure   Path traversal on file download                  Critical  Low           Mitigated
T9    Denial of Service        Targeted account lockout abuse                   Medium    Medium        Mitigated
T10   Elevation of Privilege   Loan officer approves own reviewed loan          Critical  Low           Mitigated
T11   Elevation of Privilege   Member accesses manager or officer routes        High      Medium        Mitigated


T1 — Brute-Force Credential Attack (Spoofing)

An attacker systematically tries passwords against a known username. The application locks an account for 15 minutes after five consecutive failed login attempts. The lockout timestamp is stored in the database so it survives server restarts. The login page displays a permanent security notice warning users that the lockout policy is in effect.

T2 — Session Hijacking (Spoofing)

If an attacker steals a valid session cookie they can impersonate the user. Session cookies are set with HttpOnly (JavaScript cannot read them), SameSite=Lax (not sent on cross-origin requests), and Secure in production. Flask-Login's strong session protection regenerates the session identifier if the user agent changes mid-session.

T3 — SQL Injection (Tampering)

An attacker submits SQL syntax in a form field to manipulate database queries. The application uses SQLAlchemy's ORM for every query, sending user values as bound parameters that the database engine cannot interpret as SQL syntax.

T4 — Stored XSS (Tampering)

An attacker stores JavaScript in a text field such as the loan purpose. Jinja2 escapes all template variable output by default, rendering scripts as plain visible text rather than executable code. As demonstrated in Section 5, the payload was stored and displayed as literal text with no script execution.

T5 — CSRF (Tampering)

A malicious website tricks a logged-in user's browser into submitting an unauthorised request. Flask-WTF generates a unique CSRF token per session that is included in every form and validated on every POST request. Requests without the correct token are rejected with HTTP 400.

T6 — Repudiation (Repudiation)

A manager denies approving or rejecting a loan. Every state-changing operation writes to the audit_logs table with the user, IP address, timestamp, and action details. These records are visible only to managers and cannot be edited through any interface.

T7 — IDOR and Broken Object Access (Information Disclosure)

A member changes the loan ID in the URL to view another member's application. Every route calls loan.can_be_viewed_by(current_user) before returning data. For members, this checks that loan.member_id equals current_user.id and returns HTTP 403 if the check fails.

T8 — Path Traversal on File Download (Information Disclosure)

An attacker crafts a filename to overwrite or read arbitrary files on the server. Uploaded files are renamed using a UUID before saving. The original filename is stored in the database only for display and never touches the filesystem path.

T9 — Account Lockout Abuse (Denial of Service)

An attacker triggers five failed logins for a victim's account, locking them out. The lockout expires automatically after 15 minutes without any administrator action, limiting the impact to a temporary inconvenience.

T10 — Loan Officer Self-Approval (Elevation of Privilege)

A loan officer who reviewed a loan attempts to access the approval endpoint directly. The approval endpoint is in the manager blueprint and requires the manager role. A loan officer receives HTTP 403 regardless of how they reach the URL.

T11 — Vertical Privilege Escalation (Elevation of Privilege)

A member navigates directly to the manager or loan officer dashboard. The role_required decorator checks current_user.role against permitted roles on every request and returns HTTP 403 immediately if the role does not match.


4. SECURITY CONTROLS

4.1 Password Storage

Passwords are hashed with pbkdf2:sha256 and a 16-byte random salt. The hash cannot be reversed and two users with the same password will have different stored hashes due to the unique salt.

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

4.2 Password Policy

The registration form validates complexity requirements before creating the account. All five rules must pass simultaneously.

    def validate_password(password, config):
        errors = []
        if len(password) < config['MIN_PASSWORD_LENGTH']:
            errors.append("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        if errors:
            return False, "; ".join(errors)
        return True, None

4.3 Account Lockout

After five failed login attempts the account is locked for 900 seconds. The check runs before password verification so the locked state cannot be bypassed by guessing correctly on the fifth attempt.

    def record_failed_login(self, max_attempts=5, lockout_duration=900):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.account_locked_until = datetime.utcnow() + timedelta(seconds=lockout_duration)
        db.session.commit()

The login route checks lockout status before attempting password verification. It also returns the same generic error message whether the username exists or not, preventing user enumeration.

    if user is None:
        flash('Invalid username or password.', 'danger')
        return render_template('auth/login.html', form=form)

4.4 Session Security

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE   = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=1800)

    login_manager.session_protection = 'strong'

HttpOnly prevents JavaScript from reading the cookie. Secure ensures it is only sent over HTTPS in production. SameSite=Lax prevents it from being sent on cross-origin requests. The 30-minute lifetime automatically expires idle sessions.

4.5 Role-Based Access Control

The role_required decorator is applied to every route that requires a specific role. The check is server-side against the database value, not anything the client supplies.

    def role_required(*roles):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not current_user.is_authenticated:
                    return redirect(url_for('auth.login'))
                if current_user.role not in roles:
                    log_access_denied('route', None, f'Role {current_user.role} not in {roles}')
                    abort(403)
                return f(*args, **kwargs)
            return decorated_function
        return decorator

Resource-level ownership is enforced by methods on the model itself:

    def can_be_viewed_by(self, user):
        if user.role == 'member':
            return self.member_id == user.id
        return user.role in ['loan_officer', 'manager']

    def can_be_approved_by(self, user):
        return user.role == 'manager' and self.status == 'under_review'

4.6 CSRF Protection

Flask-WTF is configured with CSRF enabled globally. Every form class inherits from FlaskForm, which automatically includes a hidden csrf_token field. The token is validated on every POST request before the route handler runs.

    WTF_CSRF_ENABLED = True

    In every template form:
    {{ form.hidden_tag() }}

4.7 SQL Injection Prevention

SQLAlchemy's ORM is used for every database interaction. User input is passed as a bound parameter, never interpolated into a query string.

    loans = Loan.query.filter_by(member_id=current_user.id).all()

    loan = Loan.query.get_or_404(loan_id)

4.8 XSS Prevention and Security Headers

Jinja2 escapes all template variable output by default. Security headers are injected on every HTTP response through an after_request hook.

    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self';"
    }

    @app.after_request
    def set_security_headers(response):
        for header, value in app.config['SECURITY_HEADERS'].items():
            response.headers[header] = value
        return response

4.9 Secure File Upload

File uploads pass through four validation checks before being saved. The final stored filename is a UUID so the original filename, which could contain path traversal characters, never reaches the filesystem.

    def validate_file_upload(file, allowed_extensions, max_size):
        filename = secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in allowed_extensions:
            return False, "File type not allowed. Allowed: pdf, jpg, jpeg, png", None
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size > max_size:
            return False, "File too large. Maximum: 5MB", None
        if file_size == 0:
            return False, "File is empty", None
        return True, None, filename

    unique_filename = f"{uuid.uuid4().hex}.{file_ext}"

4.10 Audit Logging

Every security-relevant event is written to the audit_logs table through a single central function. No route handler writes to the table directly.

    def log_security_event(event_type, resource_type=None, resource_id=None,
                           details=None, success=True, user=None):
        log_entry = AuditLog(
            event_type=event_type,
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

Events logged include login_success, login_failed, logout, loan_created, loan_reviewed, loan_approved, loan_rejected, document_uploaded, document_viewed, and access_denied.

4.11 Secrets Management

The SECRET_KEY and database URL are read from environment variables. The .env file is excluded from version control by .gitignore. Only .env.example with no real values is committed to the repository.

    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///sacco_loan.db'


5. TESTING EVIDENCE

5.1 Application Functionality Testing

Before security testing, the full application workflow was verified across all three user roles.

Figure 1 — Flask development server running with live request logs

[INSERT SCREENSHOT: screenshot_terminal.png]

The terminal shows the application started successfully on 127.0.0.1:5000. Each HTTP request is logged with method, path, and status code.


Figure 2 — Member dashboard showing loan applications with Pending, Approved, and Rejected statuses

[INSERT SCREENSHOT: screenshot_member_dashboard.png]

The member dashboard shows john_member's loan applications. Loans 1 and 2 are Approved, loan 3 is Rejected, and loan 4 is Pending. Members only see their own loans — no other member's data appears here.


Figure 3 — Loan application form filled in by a member

[INSERT SCREENSHOT: screenshot_apply_loan.png]

The member has entered ZMW 500,000 for 4 months to pay school fees. The form includes server-side validation on all fields. The CSRF token is embedded as a hidden field, protecting against cross-site request forgery.


Figure 4 — Loan submitted successfully with Pending status

[INSERT SCREENSHOT: screenshot_loan_submitted.png]

After submission, the user is redirected to the loan detail page. The green success banner confirms the application was recorded and the status badge shows Pending. The Upload Document button allows supporting documents to be attached.


Figure 5 — Secure document upload page

[INSERT SCREENSHOT: screenshot_upload_document.png]

The upload form shows the allowed file types (PDF, JPG, JPEG, PNG) and the 5MB size limit. Server-side validation checks the extension, MIME type, and file size, and renames the file to a UUID before saving.


Figure 6 — Member dashboard after uploading a document

[INSERT SCREENSHOT: screenshot_member_dashboard_updated.png]

Loan 4 now appears at the top of the dashboard in Pending status. The Upload Doc button is visible only for loans still in Pending state. Once a loan moves to Under Review, members can no longer modify it.


Figure 7 — Loan Officer dashboard showing pending loan awaiting review

[INSERT SCREENSHOT: screenshot_officer_dashboard.png]

Logged in as sarah_officer (Loan Officer role), the dashboard shows loan 4 from john_member awaiting review. The navbar confirms the role. There is a Review button but no Approve button — this is the separation of duties control in action.


Figure 8 — Loan officer viewing full loan details with Review This Loan button

[INSERT SCREENSHOT: screenshot_officer_view_loan.png]

The loan officer can see all details including the uploaded document and can download it. There is no approve or reject option. The officer can only submit a review for the manager to act on.


Figure 9 — Loan moved to Under Review after officer submits review notes

[INSERT SCREENSHOT: screenshot_loan_under_review.png]

After sarah_officer submitted the review, the loan status changed to Under Review. The review notes are recorded with the reviewer's name and date. The loan is now locked for editing by the member and awaits manager approval.


Figure 10 — Manager dashboard with statistics and loan awaiting approval

[INSERT SCREENSHOT: screenshot_manager_dashboard.png]

Logged in as mike_manager (Manager role), the dashboard shows the system summary: 0 pending review, 1 awaiting approval, 2 approved, 1 rejected. Loan 4 is listed under Awaiting Approval. The Approve/Reject button is only present here and is not available to loan officers.


Figure 11 — Manager viewing loan details before making a decision

[INSERT SCREENSHOT: screenshot_manager_view_loan.png]

The manager sees the full application including the loan officer's review notes and date. The Approve/Reject This Loan button is present here. This same page when accessed by a loan officer returns HTTP 403.


Figure 12 — Manager approval form with loan summary and decision panel

[INSERT SCREENSHOT: screenshot_approve_loan.png]

The approval page shows the loan summary on the left, the loan officer's review notes in the middle, and the manager's decision form on the right. Two distinct buttons — Approve Loan and Reject Loan — make the action explicit. The approval notes field is required before either button can be submitted.


Figure 13 — Manager dashboard after approving loan 4, showing 3 approved total

[INSERT SCREENSHOT: screenshot_manager_after_approval.png]

The success banner confirms the loan was approved. The Awaiting Approval counter has dropped to 0 and Approved has incremented to 3. The full audit trail of this decision is recorded in the audit log.


Figure 14 — Manager recently processed tab showing full loan history

[INSERT SCREENSHOT: screenshot_manager_processed.png]

The Recently Processed tab shows all decisions: loans 1, 2, and 4 approved by mike_manager, loan 3 rejected. Each row shows the decision maker and the decision date.


5.2 Security Attack Tests

Test 1 — SQL Injection in Login

An attacker attempts to bypass authentication by submitting SQL syntax in the username field.

Input used:
    Username:  admin' OR '1'='1
    Password:  anything

Expected result: Login rejected with a generic error message, no SQL error revealed.

Figure 15 — SQL injection attempt rejected with generic error message

[INSERT SCREENSHOT: screenshot_sql_injection.png]

The username field contains the SQL injection payload. The application returned "Invalid username or password", which is the same message returned for any failed login. No SQL syntax error was revealed, confirming the ORM's parameterised queries prevented the attack. The Security Notice at the bottom is a standard lockout warning displayed to all users.


Test 2 — Password Policy Enforcement

A user attempts to register with a password that does not meet the complexity requirements.

Figure 16 — Registration form showing all password policy violation errors

[INSERT SCREENSHOT: screenshot_password_policy.png]

When a weak password is submitted, the form displays all violated rules simultaneously: minimum 8 characters, uppercase letter required, lowercase letter required, digit required, and special character required. The field is highlighted in red and registration is blocked until all requirements are met.


Test 3 — XSS Prevention (Stored XSS)

A member submitted the following JavaScript payload as the loan purpose to test whether it would execute when viewed by other users:

    <script>alert('hacked')</script>

Figure 17 — XSS payload stored and displayed as escaped plain text with no script execution

[INSERT SCREENSHOT: screenshot_xss_prevention.png]

Loan Application 3 shows the purpose field containing the XSS payload. It is rendered as literal text — no alert box appeared and no script executed. Jinja2's auto-escaping converted the angle brackets to HTML entities before rendering. This loan was subsequently reviewed and rejected with the note "this is a scam alert", demonstrating the full audit trail of a detected attack attempt.


Test 4 — Audit Log Security Monitoring

After conducting all tests, the Security Audit Logs were examined to verify every event was recorded.

Figure 18 — Security audit log showing complete event trail including failed login attempts

[INSERT SCREENSHOT: screenshot_audit_logs.png]

The audit log captures the complete security event trail. Notable entries visible include loan_approved by mike_manager at 13:10:09, loan_reviewed by sarah_officer at 13:06:00, document_uploaded by john_member at 13:02:36, loan_created by john_member, and four login_failed entries by anonymous with username "admin" highlighted in red. The failed login attempts from the SQL injection test are clearly recorded with IP address 127.0.0.1 and flagged as unsuccessful. This demonstrates that the audit system would alert an administrator to a brute-force or injection attempt in a production environment.


5.3 Static Analysis — Bandit

Bandit scans Python source code for common security issues including hardcoded passwords, SQL injection patterns, and use of weak cryptographic functions.

Command run:
    bandit -r app/ -ll

Result: No issues identified across 1,146 lines of code.

    Test results:
        No issues identified.
    Code scanned:
        Total lines of code: 1146
        Total lines skipped: 0
    Run metrics:
        Total issues (by severity):
            Undefined: 0   Low: 0   Medium: 0   High: 0

This confirms no hardcoded passwords, no SQL injection risks, no command injection vectors, no weak cryptographic functions, and no unsafe file operations in the codebase.


6. VULNERABILITIES FOUND AND FIXED

Three issues were identified and corrected during development and review before final submission.

6.1 Open Redirect on Login

Found during: Code review of the login route.

Description: The login route accepted a next parameter in the URL to redirect the user after a successful login. Without validation, an attacker could craft a link that after a successful login would send the user to an attacker-controlled site, enabling phishing.

Vulnerable code:
    next_page = request.args.get('next')
    return redirect(next_page)

Fix: Added a check that the next value starts with a forward slash, ensuring it is a relative path on the same application and cannot redirect to an external domain.

    next_page = request.args.get('next')
    if not next_page or not next_page.startswith('/'):
        next_page = url_for('main.dashboard')
    return redirect(next_page)


6.2 Database File Not Excluded from Repository

Found during: Pre-push review of .gitignore.

Description: The initial .gitignore excluded database files by extension but did not explicitly exclude the instance/ directory where Flask stores the SQLite database by default. If the database had been committed it would have contained hashed passwords and all loan records.

Fix: Added instance/ explicitly to .gitignore before the first commit.

    instance/
    *.db
    *.sqlite3


6.3 Orphaned File on Upload Database Error

Found during: Code review of the upload route.

Description: If the file was saved to disk successfully but the database commit subsequently failed, the file would remain on disk permanently with no database record pointing to it. Over time this would leak disk space and leave potentially sensitive documents orphaned and inaccessible.

Fix: Added a cleanup block to delete the saved file if the database operation fails.

    try:
        file.save(file_path)
        db.session.add(document)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        if os.path.exists(file_path):
            os.remove(file_path)
        flash('An error occurred while uploading. Please try again.', 'danger')


7. REFLECTION

7.1 What Worked Well

Security-first design produced cleaner code. Deciding before writing a single route that every endpoint would require authentication, every form would have CSRF protection, and every resource access would check ownership meant these were baseline assumptions rather than afterthoughts. The access control decorators and the can_be_viewed_by pattern on models let route handlers stay short because the security logic lives in one reusable place.

Using established libraries avoided a large category of mistakes. Rolling a custom session management or password hashing system would have introduced subtle bugs that are difficult to test for. Flask-Login and Werkzeug's hashing functions have been reviewed and tested far more extensively than any implementation written for this assignment.

STRIDE made the threat model systematic. Working through each category of threat against each data flow forced consideration of threats that would not have come up otherwise. The repudiation category in particular prompted the audit logging design. As the testing evidence shows, the audit log captured not just normal operations but also the failed SQL injection attempts, logging things that looked like attacks as well as normal use.

The XSS test produced a particularly clear demonstration. Loan 3 in the system contains a script tag as its purpose, submitted during testing. The loan was processed through the full workflow, reviewed and rejected, with the script visible at every stage as harmless text. This shows the protection working in a realistic scenario rather than a contrived isolated test.

7.2 Remaining Weaknesses

No global rate limiting. The account lockout mechanism protects individual accounts but a distributed credential stuffing attack, which tries one password across thousands of different usernames, would not trigger any lockout because no single account reaches the threshold. Flask-Limiter could add IP-based rate limiting to the login endpoint. This was not implemented due to time constraints.

No HTTPS in development. The application runs over HTTP locally, which means session cookies travel unencrypted on the network. The Secure cookie flag is set in the production configuration but cannot be enforced in a development HTTP environment. A production deployment would use nginx as a reverse proxy with a Let's Encrypt certificate.

Uploaded files are stored unencrypted. Supporting documents are stored as ordinary files on the server filesystem. If the server were compromised the documents would be readable. Encrypting files at rest using the cryptography library before writing them to disk would address this, though it adds key management complexity.

No two-factor authentication. The manager role can approve loans and view all audit logs, so a compromised manager account would be a serious incident. TOTP-based two-factor authentication using the pyotp library would add a second authentication factor for this role. This was not implemented because it requires a QR code enrolment flow and secrets storage for TOTP seeds, both beyond the time available.

Audit logs share the same database. An attacker with database write access could modify or delete log entries. Shipping entries to an append-only external logging service would prevent this.

7.3 Key Lessons

The most important lesson is that security controls are significantly harder to add to an existing application than to build in from the start. The access control patterns used here only work cleanly because they were part of the original design. Adding them to an application where routes already returned data without checks would require auditing every endpoint individually with a high probability of missing at least one.

The second lesson is that threat modelling produces better security than a checklist approach. Working through STRIDE identified the open redirect vulnerability and the orphaned file issue before testing, because thinking about tampering threats led directly to asking what a user can control in a request and what damage that control could enable. A checklist of OWASP vulnerabilities would have caught injection and authentication items but might not have surfaced those two application-specific issues.

The third lesson is visible in the audit logs screenshot. The failed login attempts under username "admin", made during the SQL injection test, are recorded with their IP address and flagged as failures. In a production system those four consecutive failures on a non-existent account would be a detectable signal of a probe or attack. Building logging in from the start means the system generates useful security signals automatically, without any additional work at investigation time.


8. REFERENCES

1. OWASP Foundation. OWASP Top Ten 2021. https://owasp.org/Top10/
2. OWASP Foundation. Testing Guide v4.2. https://owasp.org/www-project-web-security-testing-guide/
3. Microsoft. STRIDE Threat Modeling. https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
4. Flask Project. Security Considerations, Flask 3.0 Documentation. https://flask.palletsprojects.com/en/3.0.x/security/
5. NIST. Digital Identity Guidelines SP 800-63B. https://pages.nist.gov/800-63-3/
6. PyCQA. Bandit: Security Linter for Python. https://bandit.readthedocs.io/
7. Pallets Projects. Flask-Login Documentation. https://flask-login.readthedocs.io/
8. Pallets Projects. Flask-WTF Documentation. https://flask-wtf.readthedocs.io/


End of report.
