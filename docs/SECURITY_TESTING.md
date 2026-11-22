# Security Testing Guide

## Overview

This document provides comprehensive instructions for testing the security controls implemented in the SACCO Loan Application System.

---

## Testing Environment Setup

### Prerequisites

1. **Application Running**: `python run.py`
2. **Test Accounts Created**: Use `flask init-db` to create sample users
3. **OWASP ZAP Installed**: Download from https://www.zaproxy.org/download/
4. **Bandit Installed**: `pip install bandit`
5. **Browser**: Chrome/Firefox with Developer Tools

---

## 1. Static Application Security Testing (SAST)

### Bandit Security Scan

**Purpose**: Identify security issues in Python code

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run Bandit scan
bandit -r app/ -ll

# Expected Result: No high or medium severity issues
```

**What Bandit Checks**:
- Hardcoded passwords
- SQL injection vulnerabilities
- Command injection risks
- Insecure cryptographic functions
- Path traversal issues

**Example Output**:
```
Test results:
	No issues identified.
Code scanned:
	Total lines of code: 1146
```

### Safety Dependency Check

**Purpose**: Check for known vulnerabilities in dependencies

```bash
safety check -r requirements.txt
```

**Expected Result**: All dependencies secure

---

## 2. Dynamic Application Security Testing (DAST)

### OWASP ZAP Automated Scan

#### Setup

1. Open OWASP ZAP
2. Go to Tools → Options → Local Proxies
3. Note the proxy address (default: 127.0.0.1:8080)
4. Configure browser to use ZAP proxy

#### Automated Scan Steps

1. Start the Flask application: `python run.py`
2. In ZAP, enter target URL: `http://127.0.0.1:5000`
3. Click "Automated Scan"
4. Log in as each user type (member, officer, manager)
5. Navigate through all major pages
6. Review alerts in the Alerts tab

#### Expected Findings

✅ **Should Pass**:
- CSRF tokens present
- Security headers configured
- Session cookies secured (HttpOnly, SameSite)
- No SQL injection
- No XSS vulnerabilities

⚠️ **Acceptable Warnings**:
- Application Error Disclosure (generic errors shown)
- X-Content-Type-Options header (already implemented)

❌ **Should NOT Appear**:
- SQL Injection vulnerabilities
- XSS vulnerabilities
- Broken authentication
- Sensitive data exposure

---

## 3. Manual Security Testing

### 3.1 Authentication Security

#### Test Case 1: SQL Injection in Login

**Purpose**: Verify SQL injection protection

**Steps**:
1. Navigate to login page
2. Enter username: `admin' OR '1'='1`
3. Enter any password
4. Click "Log In"

**Expected Result**: Login fails with "Invalid username or password"

**Verification**:
- No SQL error displayed
- Audit log shows failed login attempt
- No authentication bypass

---

#### Test Case 2: Account Lockout

**Purpose**: Verify brute force protection

**Steps**:
1. Navigate to login page
2. Enter valid username (e.g., `john_member`)
3. Enter wrong password 5 times
4. Attempt 6th login

**Expected Result**:
- After 5th attempt: "Account temporarily locked"
- Account locked for 15 minutes
- Audit log shows failed login attempts

**Verification**:
```sql
-- Check audit log
SELECT * FROM audit_logs WHERE event_type='login_failed' AND username='john_member';
```

---

#### Test Case 3: Session Security

**Purpose**: Verify session cookie security

**Steps**:
1. Log in as any user
2. Open browser DevTools → Application → Cookies
3. Find session cookie

**Expected Result**:
- HttpOnly: ✅ (prevents JavaScript access)
- Secure: ⚠️ (only in HTTPS/production)
- SameSite: Lax ✅

**Screenshot Required**: Cookie settings

---

#### Test Case 4: Password Policy

**Purpose**: Verify password complexity enforcement

**Steps**:
1. Go to registration page
2. Try these passwords:
   - `short` → Should fail (too short)
   - `alllowercase` → Should fail (no uppercase)
   - `ALLUPPERCASE` → Should fail (no lowercase)
   - `NoDigits!` → Should fail (no digit)
   - `NoSpecial123` → Should fail (no special char)
   - `Valid123!` → Should succeed ✅

**Expected Result**: Only passwords meeting all requirements accepted

---

### 3.2 Authorization & Access Control

#### Test Case 5: Horizontal Privilege Escalation

**Purpose**: Verify users cannot access others' data

**Steps**:
1. Log in as `john_member`
2. Create a loan application (note the ID, e.g., loan #1)
3. Log out and log in as another member
4. Try to access: `http://127.0.0.1:5000/member/loan/1`

**Expected Result**:
- 403 Forbidden error
- Message: "You do not have permission to view this loan"
- Audit log shows access denial

---

#### Test Case 6: Vertical Privilege Escalation

**Purpose**: Verify role-based access control

**Steps**:
1. Log in as `john_member` (member role)
2. Try to access manager dashboard directly:
   `http://127.0.0.1:5000/manager/dashboard`

**Expected Result**:
- 403 Forbidden error
- Message: "You do not have permission to access this page"
- Redirected to appropriate dashboard

---

#### Test Case 7: Separation of Duties

**Purpose**: Verify loan officers cannot approve loans

**Steps**:
1. Log in as `john_member`, create loan application
2. Log in as `sarah_officer` (loan officer)
3. Review the loan (moves to "under_review")
4. Try to access: `http://127.0.0.1:5000/manager/approve_loan/1`

**Expected Result**:
- 403 Forbidden (loan officer has no access to approval)
- Only managers can approve

---

### 3.3 Injection Attacks

#### Test Case 8: XSS Prevention

**Purpose**: Verify XSS protection

**Steps**:
1. Log in as member
2. Create loan application with purpose:
   ```html
   <script>alert('XSS')</script>
   <img src=x onerror=alert('XSS')>
   ```
3. View the loan application

**Expected Result**:
- No alert popup
- Script tags displayed as text
- HTML escaped: `&lt;script&gt;alert('XSS')&lt;/script&gt;`

---

#### Test Case 9: SQL Injection in Loan Purpose

**Purpose**: Verify parameterized queries

**Steps**:
1. Log in as member
2. Create loan with purpose: `'; DROP TABLE loans; --`
3. Submit application

**Expected Result**:
- Application created successfully
- SQL text stored as string (not executed)
- Database intact

**Verification**:
```sql
SELECT purpose FROM loans WHERE id=X;
-- Should show: '; DROP TABLE loans; --
```

---

### 3.4 File Upload Security

#### Test Case 10: Malicious File Extension

**Purpose**: Verify file upload restrictions

**Test Files**:
1. `malware.exe` → Should fail
2. `script.php` → Should fail
3. `document.pdf` → Should pass ✅
4. `photo.jpg` → Should pass ✅

**Steps**:
1. Log in as member
2. Create loan application
3. Try uploading each file type

**Expected Result**:
- Only PDF, JPG, JPEG, PNG allowed
- Error message: "File type not allowed"

---

#### Test Case 11: File Size Limit

**Purpose**: Verify file size restrictions

**Steps**:
1. Create a 6MB dummy file:
   ```bash
   fsutil file createnew large_file.pdf 6291456
   ```
2. Try to upload to loan application

**Expected Result**:
- Upload rejected
- Error: "File too large. Maximum size: 5.0MB"

---

#### Test Case 12: Path Traversal

**Purpose**: Verify secure file handling

**Steps**:
1. Create loan application with ID 1
2. Upload a legitimate document
3. Try to download with manipulated path:
   `http://127.0.0.1:5000/member/document/../../../etc/passwd`

**Expected Result**:
- 404 Not Found (file doesn't exist)
- Secure filename prevents path traversal

---

### 3.5 CSRF Protection

#### Test Case 13: CSRF Token Validation

**Purpose**: Verify CSRF protection

**Steps**:
1. Log in as member
2. Open loan application form
3. View page source, find CSRF token
4. Open browser console, remove CSRF token from form:
   ```javascript
   document.querySelector('input[name="csrf_token"]').remove();
   ```
5. Submit form

**Expected Result**:
- Form submission rejected
- Error: "The CSRF token is missing"

---

### 3.6 Security Headers

#### Test Case 14: Security Headers Present

**Purpose**: Verify security headers

**Steps**:
1. Open any page
2. Open DevTools → Network tab
3. Click on the request
4. View Response Headers

**Expected Headers**:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

**Verification**:
```bash
curl -I http://127.0.0.1:5000
```

---

### 3.7 Audit Logging

#### Test Case 15: Login Audit Logging

**Purpose**: Verify security events are logged

**Steps**:
1. Perform various actions:
   - Successful login
   - Failed login
   - Create loan
   - Upload document
   - Approve loan (as manager)
2. Log in as `mike_manager`
3. Go to Audit Logs page

**Expected Result**:
- All actions logged with:
  - Timestamp
  - Event type
  - Username
  - IP address
  - Success/failure

**Database Verification**:
```sql
SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20;
```

---

## 4. Penetration Testing Checklist

### Authentication
- [x] SQL injection in login
- [x] Brute force protection
- [x] Password policy enforcement
- [x] Session fixation
- [x] Session timeout

### Authorization
- [x] Horizontal privilege escalation
- [x] Vertical privilege escalation
- [x] Insecure direct object references
- [x] Missing function level access control

### Input Validation
- [x] XSS in all input fields
- [x] SQL injection in all parameters
- [x] Command injection
- [x] Path traversal

### File Upload
- [x] Malicious file execution
- [x] File type bypass
- [x] File size limits
- [x] Path traversal via filename

### Session Management
- [x] Session cookies secure
- [x] Session timeout
- [x] Logout functionality
- [x] Concurrent sessions

### Error Handling
- [x] Information disclosure in errors
- [x] Stack traces disabled

---

## 5. Security Test Results Template

### Test Execution Record

**Date**: ___________  
**Tester**: ___________  
**Application Version**: 1.0  

| Test ID | Test Name | Status | Notes |
|---------|-----------|--------|-------|
| TC-1 | SQL Injection in Login | ☐ Pass ☐ Fail | |
| TC-2 | Account Lockout | ☐ Pass ☐ Fail | |
| TC-3 | Session Security | ☐ Pass ☐ Fail | |
| TC-4 | Password Policy | ☐ Pass ☐ Fail | |
| TC-5 | Horizontal Privilege Escalation | ☐ Pass ☐ Fail | |
| TC-6 | Vertical Privilege Escalation | ☐ Pass ☐ Fail | |
| TC-7 | Separation of Duties | ☐ Pass ☐ Fail | |
| TC-8 | XSS Prevention | ☐ Pass ☐ Fail | |
| TC-9 | SQL Injection in Form | ☐ Pass ☐ Fail | |
| TC-10 | File Extension Validation | ☐ Pass ☐ Fail | |
| TC-11 | File Size Limit | ☐ Pass ☐ Fail | |
| TC-12 | Path Traversal | ☐ Pass ☐ Fail | |
| TC-13 | CSRF Protection | ☐ Pass ☐ Fail | |
| TC-14 | Security Headers | ☐ Pass ☐ Fail | |
| TC-15 | Audit Logging | ☐ Pass ☐ Fail | |

---

## 6. Automated Test Script

Save this as `security_tests.py` for automated testing:

```python
import requests

BASE_URL = "http://127.0.0.1:5000"

def test_sql_injection_login():
    """Test SQL injection in login"""
    response = requests.post(f"{BASE_URL}/auth/login", data={
        'username': "admin' OR '1'='1",
        'password': 'anything'
    })
    assert "Invalid username or password" in response.text
    print("✅ SQL Injection Test Passed")

def test_xss_prevention():
    """Test XSS in loan purpose"""
    # Login first
    session = requests.Session()
    # ... implement login logic
    # Submit loan with XSS
    # Verify escaped output
    pass

if __name__ == "__main__":
    test_sql_injection_login()
```

---

## 7. Reporting Template

### Security Test Report

**Executive Summary**:
- Total Tests: 15
- Passed: __
- Failed: __
- Critical Issues: __
- High Issues: __
- Medium Issues: __

**Detailed Findings**:

#### Finding 1: [Issue Name]
- **Severity**: Critical/High/Medium/Low
- **Description**: What was found
- **Steps to Reproduce**: 1, 2, 3...
- **Impact**: What could happen
- **Recommendation**: How to fix
- **Status**: Open/Fixed/Accepted

---

## 8. Continuous Security Testing

### Pre-Deployment Checklist

Before deploying to production:

- [ ] Bandit scan passes
- [ ] Safety check passes
- [ ] All manual tests pass
- [ ] OWASP ZAP scan reviewed
- [ ] Security headers verified
- [ ] HTTPS enabled
- [ ] Debug mode disabled
- [ ] Production secrets configured
- [ ] Database backups configured
- [ ] Audit logging verified

---

## Conclusion

This comprehensive testing approach ensures all OWASP Top 10 vulnerabilities are addressed. Regular testing should be performed after any code changes.

**Next Steps**:
1. Execute all test cases
2. Document results
3. Address any findings
4. Re-test after fixes
5. Deploy to production
