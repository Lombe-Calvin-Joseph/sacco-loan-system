# SACCO Loan System - Threat Model

## Data Flow Diagram (DFD)

### Level 0 - Context Diagram

```
┌─────────────┐         ┌─────────────────┐         ┌──────────┐
│   Member    │◄───────►│  Flask Web App  │◄───────►│ Database │
└─────────────┘         └─────────────────┘         └──────────┘
                               │                           
┌─────────────┐                │                           
│Loan Officer │◄───────────────┤                           
└─────────────┘                │                           
                               │                     ┌──────────────┐
┌─────────────┐                └────────────────────►│ File Storage │
│   Manager   │◄───────────────┘                     └──────────────┘
└─────────────┘                                             

                                                      ┌──────────────┐
                                                      │  Audit Logs  │
                                                      └──────────────┘
```

### Trust Boundaries

1. **Internet ↔ Web Application**: HTTPS (TLS boundary)
2. **Web Application ↔ Database**: Internal, trusted (same server)
3. **Web Application ↔ File System**: Internal, trusted (same server)

---

## STRIDE Threat Analysis

### 1. Spoofing Identity

#### Threat 1.1: Credential Theft & Brute Force
- **Description**: Attacker attempts to gain unauthorized access by guessing passwords or using stolen credentials
- **Impact**: High - Unauthorized access to loan applications and sensitive data
- **Likelihood**: Medium - Common attack vector
- **Affected Component**: Authentication system
- **Mitigation**:
  - Strong password policy (8+ chars, mixed case, digits, special chars)
  - Account lockout after 5 failed attempts
  - 15-minute lockout duration
  - Password hashing with bcrypt/pbkdf2
  - Session timeout (30 minutes)
- **Testing**: Manual brute force attempts, verify lockout mechanism
- **Status**: ✅ Mitigated

#### Threat 1.2: Session Hijacking
- **Description**: Attacker steals session cookie to impersonate authenticated user
- **Impact**: High - Full account access
- **Likelihood**: Low - Requires network access or XSS
- **Affected Component**: Session management
- **Mitigation**:
  - HTTPOnly cookies (prevent JavaScript access)
  - Secure flag in production (HTTPS only)
  - SameSite=Lax (CSRF protection)
  - Strong session protection (Flask-Login)
  - Session regeneration on login
- **Testing**: Inspect cookies in browser DevTools, verify flags
- **Status**: ✅ Mitigated

---

### 2. Tampering with Data

#### Threat 2.1: SQL Injection
- **Description**: Attacker injects SQL commands to modify data or bypass authentication
- **Impact**: Critical - Full database compromise, data theft, data destruction
- **Likelihood**: Medium - Common attack, but well-known defenses
- **Affected Component**: All database queries
- **Mitigation**:
  - SQLAlchemy ORM with parameterized queries
  - No raw SQL queries
  - Input validation on all fields
- **Testing**: Bandit static analysis, manual injection attempts (`admin' OR '1'='1`)
- **Status**: ✅ Mitigated

#### Threat 2.2: Loan Application Manipulation
- **Description**: Member modifies another user's loan application
- **Impact**: High - Fraudulent loan approvals, data integrity violation
- **Likelihood**: Low - Requires bypassing access controls
- **Affected Component**: Loan editing endpoints
- **Mitigation**:
  - Server-side ownership checks (`can_be_edited_by`)
  - Access control decorators (`@owns_resource`)
  - Authorization before every sensitive operation
- **Testing**: Manual attempts to edit other users' loans via URL manipulation
- **Status**: ✅ Mitigated

#### Threat 2.3: CSRF (Cross-Site Request Forgery)
- **Description**: Attacker tricks user into submitting unauthorized requests
- **Impact**: High - Unauthorized loan applications, approvals
- **Likelihood**: Medium - Requires user to visit malicious site while authenticated
- **Affected Component**: All state-changing endpoints (POST, PUT, DELETE)
- **Mitigation**:
  - Flask-WTF CSRF protection enabled
  - CSRF tokens in all forms
  - SameSite cookie attribute
- **Testing**: Submit form without CSRF token, verify rejection
- **Status**: ✅ Mitigated

---

### 3. Repudiation

#### Threat 3.1: User Denies Loan Approval/Rejection
- **Description**: Manager claims they didn't approve or reject a loan
- **Impact**: Medium - Legal disputes, compliance issues
- **Likelihood**: Low - Internal threat
- **Affected Component**: Loan approval workflow
- **Mitigation**:
  - Comprehensive audit logging (user, timestamp, IP, action)
  - Immutable audit log (append-only)
  - Manager can view audit logs
  - User agent tracking
- **Testing**: Perform actions, verify audit log entries
- **Status**: ✅ Mitigated

#### Threat 3.2: Audit Log Tampering
- **Description**: Attacker modifies or deletes audit logs to cover tracks
- **Impact**: High - Evidence destruction, compliance violation
- **Likelihood**: Low - Requires database access
- **Affected Component**: Audit log database table
- **Mitigation**:
  - Database-level permissions (read-only for most users)
  - Separate audit log table with timestamps
  - Future: External log aggregation (Splunk, ELK)
- **Testing**: Attempt to modify audit log records
- **Status**: ⚠️ Partially mitigated (database-level controls needed)

---

### 4. Information Disclosure

#### Threat 4.1: Unauthorized Loan Data Access
- **Description**: Member views another member's loan application
- **Impact**: High - Privacy breach, GDPR/data protection violation
- **Likelihood**: Medium - Common authorization flaw
- **Affected Component**: All loan viewing endpoints
- **Mitigation**:
  - Resource-level access control (`can_be_viewed_by`)
  - Server-side authorization on every request
  - Role-based access control
  - Access denial logging
- **Testing**: Attempt to access `/member/loan/999` (another user's loan)
- **Status**: ✅ Mitigated

#### Threat 4.2: Document Leakage via Path Traversal
- **Description**: Attacker downloads files outside upload directory
- **Impact**: Critical - Server compromise, credential theft
- **Likelihood**: Low - Well-known attack, standard defenses
- **Affected Component**: File download endpoint
- **Mitigation**:
  - Secure filename generation (UUID-based)
  - `secure_filename()` sanitization
  - Files stored in user-specific subdirectories
  - Access control before serving files
- **Testing**: Attempt to download `../../../etc/passwd`
- **Status**: ✅ Mitigated

#### Threat 4.3: Verbose Error Messages
- **Description**: Stack traces or detailed errors reveal system internals
- **Impact**: Medium - Information gathering for attacks
- **Likelihood**: Medium - Depends on configuration
- **Affected Component**: Error handling
- **Mitigation**:
  - Debug mode disabled in production
  - Generic error messages for users
  - Detailed errors logged server-side only
- **Testing**: Trigger errors, verify generic messages
- **Status**: ⚠️ Requires production deployment verification

---

### 5. Denial of Service

#### Threat 5.1: Account Lockout Abuse
- **Description**: Attacker locks out legitimate users by triggering failed logins
- **Impact**: Medium - Service unavailability for targeted users
- **Likelihood**: Medium - Easy to execute
- **Affected Component**: Login endpoint
- **Mitigation**:
  - 15-minute automatic unlock
  - Lockout threshold balanced (5 attempts)
  - Failed login logging for investigation
  - Future: CAPTCHA after 3 attempts
- **Testing**: Intentionally fail login 5 times, verify lockout and auto-unlock
- **Status**: ✅ Mitigated (with limitations)

#### Threat 5.2: Large File Upload DoS
- **Description**: Attacker uploads massive files to exhaust disk space
- **Impact**: Medium - Service degradation, disk exhaustion
- **Likelihood**: Low - Requires authenticated access
- **Affected Component**: File upload endpoint
- **Mitigation**:
  - 5MB file size limit enforced
  - Server-side validation before saving
  - File type restrictions (PDF, JPG, PNG only)
- **Testing**: Attempt to upload 10MB file, verify rejection
- **Status**: ✅ Mitigated

---

### 6. Elevation of Privilege

#### Threat 6.1: Loan Officer Self-Approval
- **Description**: Loan officer attempts to approve loans without manager authorization
- **Impact**: Critical - Fraudulent loan approvals, financial loss
- **Likelihood**: Low - Requires circumventing role checks
- **Affected Component**: Loan approval endpoint
- **Mitigation**:
  - Separation of duties enforced in code
  - Only managers can approve (`@role_required('manager')`)
  - Additional check: manager cannot approve loans they reviewed
  - Authorization checks on approval endpoint
- **Testing**: Attempt to access approval endpoint as loan officer
- **Status**: ✅ Mitigated

#### Threat 6.2: Horizontal Privilege Escalation
- **Description**: Member edits or views another member's data
- **Impact**: High - Privacy breach, data manipulation
- **Likelihood**: Medium - Common authorization flaw
- **Affected Component**: All resource access endpoints
- **Mitigation**:
  - Resource ownership checks (`loan.member_id == current_user.id`)
  - `@owns_resource` decorator
  - Server-side authorization
- **Testing**: URL manipulation, direct endpoint access
- **Status**: ✅ Mitigated

#### Threat 6.3: Vertical Privilege Escalation
- **Description**: Member attempts to access admin/manager functions
- **Impact**: Critical - Full system compromise
- **Likelihood**: Low - Requires bypassing role checks
- **Affected Component**: All privileged endpoints
- **Mitigation**:
  - `@role_required` decorator on all role-specific routes
  - Role checked in database, not client-side
  - 403 response for unauthorized access
- **Testing**: Direct access to `/manager/` routes as member
- **Status**: ✅ Mitigated

---

### 7. Additional Web-Specific Threats

#### Threat 7.1: Cross-Site Scripting (XSS)
- **Description**: Attacker injects malicious JavaScript into loan purpose field
- **Impact**: High - Session hijacking, phishing, credential theft
- **Likelihood**: Medium - Common web vulnerability
- **Affected Component**: All user input rendering
- **Mitigation**:
  - Jinja2 auto-escaping enabled by default
  - Input sanitization (`sanitize_text_input`)
  - Content Security Policy header
- **Testing**: Submit `<script>alert('XSS')</script>`, verify escaping
- **Status**: ✅ Mitigated

#### Threat 7.2: Insecure File Upload
- **Description**: Attacker uploads malicious executable disguised as PDF
- **Impact**: Critical - Remote code execution, server compromise
- **Likelihood**: Low - Requires multiple defense failures
- **Affected Component**: Document upload endpoint
- **Mitigation**:
  - Extension whitelist validation (pdf, jpg, jpeg, png)
  - MIME type checking
  - File size limits (5MB)
  - Secure filename generation (UUID)
  - Files stored outside web root
- **Testing**: Upload .exe file renamed to .pdf, verify rejection
- **Status**: ✅ Mitigated

#### Threat 7.3: Clickjacking
- **Description**: Attacker embeds application in iframe to trick users
- **Impact**: Medium - UI redressing, unintended actions
- **Likelihood**: Low - Requires user to visit malicious site
- **Affected Component**: All pages
- **Mitigation**:
  - X-Frame-Options: DENY header
  - CSP frame-ancestors directive
- **Testing**: Attempt to embed in iframe, verify blocking
- **Status**: ✅ Mitigated

---

## Risk Summary

| Risk Level | Count | Status |
|------------|-------|--------|
| Critical   | 0     | All mitigated |
| High       | 0     | All mitigated |
| Medium     | 2     | Accepted/Residual |
| Low        | 0     | N/A |

### Residual Risks

1. **Audit Log Tampering** (Medium): Requires database-level controls and external log shipping
2. **Advanced DoS** (Low): No global rate limiting, only per-account lockout

---

## Threat Model Conclusion

The SACCO Loan Application System has been designed with security as a primary requirement. All critical and high-severity threats have been addressed through defense-in-depth security controls. Residual risks are documented and have known mitigation strategies for future implementation.

**Threat Model Version**: 1.0  
**Last Updated**: November 2024  
**Next Review**: Before production deployment
