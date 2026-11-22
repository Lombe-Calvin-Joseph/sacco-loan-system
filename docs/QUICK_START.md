# Quick Start Guide

## Get the Application Running in 5 Minutes

### 1. Install Dependencies (2 minutes)

```bash
# Navigate to project directory
cd "SACCO-Loan-System"

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

### 2. Initialize Database (30 seconds)

```bash
flask init-db
```

This creates three sample users:
- **Member**: `john_member` / `Password123!`
- **Loan Officer**: `sarah_officer` / `Password123!`
- **Manager**: `mike_manager` / `Password123!`

### 3. Run the Application (30 seconds)

```bash
python run.py
```

Open browser: **http://127.0.0.1:5000**

---

## Test the Application (5 minutes)

### As a Member:

1. Log in with `john_member` / `Password123!`
2. Click "Apply for Loan"
3. Fill in:
   - Amount: 10000
   - Duration: 12 months
   - Purpose: "Business expansion"
4. Submit application
5. Click "Upload Doc" and attach a PDF or image
6. View your application in the dashboard

### As a Loan Officer:

1. Log out (top right)
2. Log in with `sarah_officer` / `Password123!`
3. See all pending loans
4. Click "Review" on a loan
5. Add review notes: "All documents verified, recommend approval"
6. Submit Review (moves loan to "under_review" status)
7. **Note**: You CANNOT approve (separation of duties)

### As a Manager:

1. Log out
2. Log in with `mike_manager` / `Password123!`
3. See loans awaiting approval
4. Click "Approve/Reject"
5. Review the loan officer's notes
6. Add approval notes: "Approved for ZMW 10,000"
7. Click "Approve Loan"
8. View audit logs to see all actions

---

## Security Features Demonstration

### 1. Password Policy (1 minute)

Try registering with weak password:
- Go to Register page
- Try password: `simple` → **Rejected**
- Try password: `Simple123!` → **Accepted**

### 2. Account Lockout (1 minute)

Try brute force:
- Log out
- Try logging in with wrong password 6 times
- Account locked message appears
- Wait 15 minutes OR restart app (development mode resets)

### 3. Access Control (1 minute)

Try unauthorized access:
- Log in as member
- Create a loan (note the ID, e.g., #1)
- Log in as different member
- Try accessing: `http://127.0.0.1:5000/member/loan/1`
- **Result**: 403 Forbidden

### 4. SQL Injection Prevention (30 seconds)

Try SQL injection:
- Log out
- Username: `admin' OR '1'='1`
- Password: `anything`
- **Result**: Login fails (no SQL error)

### 5. XSS Prevention (30 seconds)

Try XSS:
- Log in as member
- Create loan with purpose: `<script>alert('XSS')</script>`
- View the loan
- **Result**: Script displayed as text, not executed

---

## Project Structure

```
SACCO-Loan-System/
├── app/
│   ├── __init__.py          # Application factory
│   ├── models.py            # Database models
│   ├── routes/              # Route handlers (auth, member, officer, manager)
│   ├── forms/               # WTForms with validation
│   ├── templates/           # HTML templates
│   ├── static/              # CSS, uploads
│   └── utils/               # Security utilities (validators, audit, decorators)
├── config/
│   └── config.py            # Security configuration
├── docs/                    # Documentation
├── run.py                   # Application entry point
├── requirements.txt         # Dependencies
└── README.md               # Comprehensive documentation
```

---

## Common Commands

```bash
# Run application
python run.py

# Initialize database
flask init-db

# Run security scan
bandit -r app/ -ll

# Check dependencies
safety check -r requirements.txt

# Access Flask shell
flask shell
```

---

## Default Test Accounts

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| john_member | Password123! | Member | Apply for loans, upload docs |
| sarah_officer | Password123! | Loan Officer | Review loans (cannot approve) |
| mike_manager | Password123! | Manager | Approve/reject loans, view audit logs |

---

## Troubleshooting

### Issue: "ModuleNotFoundError"
**Solution**: Activate virtual environment first
```bash
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux
```

### Issue: "Address already in use"
**Solution**: Port 5000 is busy, use another:
```bash
python run.py  # Then edit run.py to use port 5001
```

### Issue: Database error
**Solution**: Delete database and reinitialize:
```bash
# Delete sacco_loan.db file
flask init-db
```

### Issue: CSRF token missing
**Solution**: Ensure cookies are enabled in browser

---

## Next Steps

1. ✅ **Read README.md** - Comprehensive security documentation
2. ✅ **Review THREAT_MODEL.md** - STRIDE analysis and threat mitigation
3. ✅ **Follow SECURITY_TESTING.md** - Test all security controls
4. ✅ **Deploy to production** - Use HTTPS, configure secrets, enable security headers

---

## Production Deployment Checklist

Before deploying:

- [ ] Change SECRET_KEY in .env to random 32-byte value
- [ ] Set FLASK_ENV=production
- [ ] Enable SESSION_COOKIE_SECURE=True (requires HTTPS)
- [ ] Configure PostgreSQL (optional, SQLite works for small scale)
- [ ] Set up HTTPS (Let's Encrypt)
- [ ] Configure proper logging
- [ ] Set up database backups
- [ ] Review audit logs regularly
- [ ] Run OWASP ZAP scan
- [ ] Verify all security tests pass

---

**You're now ready to explore the secure SACCO Loan Application System!**
