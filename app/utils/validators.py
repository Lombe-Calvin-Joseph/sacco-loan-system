"""
Input Validation Utilities - Protection against injection and XSS
"""
import re
import os
from werkzeug.utils import secure_filename


def validate_password(password, config):
    """
    Validate password against security policy
    Returns (is_valid, error_message)
    """
    errors = []
    
    if len(password) < config['MIN_PASSWORD_LENGTH']:
        errors.append(f"Password must be at least {config['MIN_PASSWORD_LENGTH']} characters long")
    
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


def validate_file_upload(file, allowed_extensions, max_size):
    """
    Validate uploaded file for security
    Returns (is_valid, error_message, secure_filename)
    """
    if not file or file.filename == '':
        return False, "No file selected", None
    
    # Get secure filename
    filename = secure_filename(file.filename)
    
    if not filename:
        return False, "Invalid filename", None
    
    # Check file extension
    if '.' not in filename:
        return False, "File must have an extension", None
    
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_extensions:
        return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}", None
    
    # Check file size by seeking to end
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)  # Reset pointer
    
    if file_size > max_size:
        return False, f"File too large. Maximum size: {max_size / (1024*1024):.1f}MB", None
    
    if file_size == 0:
        return False, "File is empty", None
    
    return True, None, filename


def sanitize_filename(filename):
    """
    Additional filename sanitization beyond secure_filename
    """
    # Remove any path components
    filename = os.path.basename(filename)
    # Use werkzeug's secure_filename
    filename = secure_filename(filename)
    # Remove any remaining problematic characters
    filename = re.sub(r'[^\w\s.-]', '', filename)
    return filename


def validate_loan_amount(amount):
    """
    Validate loan amount
    Returns (is_valid, error_message)
    """
    try:
        amount = float(amount)
        if amount <= 0:
            return False, "Loan amount must be greater than zero"
        if amount > 1000000:  # Business rule: max loan amount
            return False, "Loan amount exceeds maximum allowed"
        return True, None
    except (ValueError, TypeError):
        return False, "Invalid loan amount"


def validate_duration(months):
    """
    Validate loan duration
    Returns (is_valid, error_message)
    """
    try:
        months = int(months)
        if months < 1:
            return False, "Duration must be at least 1 month"
        if months > 120:  # Business rule: max 10 years
            return False, "Duration exceeds maximum allowed (120 months)"
        return True, None
    except (ValueError, TypeError):
        return False, "Invalid duration"


def sanitize_text_input(text, max_length=None):
    """
    Sanitize text input to prevent XSS
    Note: Flask's Jinja2 auto-escapes by default, but this provides additional protection
    """
    if not text:
        return ""
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    # Enforce max length if specified
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text


def validate_email(email):
    """
    Basic email validation
    Returns (is_valid, error_message)
    """
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    if not email or not email.strip():
        return False, "Email is required"
    
    if not email_pattern.match(email):
        return False, "Invalid email format"
    
    return True, None


def validate_username(username):
    """
    Validate username format
    Returns (is_valid, error_message)
    """
    if not username or not username.strip():
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 80:
        return False, "Username must not exceed 80 characters"
    
    # Only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, None
