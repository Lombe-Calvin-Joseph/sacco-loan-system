"""
Database Models with Security Controls
"""
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    """
    User model with secure password storage and account lockout
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # member, loan_officer, manager
    
    # Account Security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    loans = db.relationship('Loan', backref='applicant', lazy='dynamic', 
                           foreign_keys='Loan.member_id')
    
    def set_password(self, password):
        """Hash and store password using bcrypt"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        """Verify password against stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return True
        elif self.account_locked_until and datetime.utcnow() >= self.account_locked_until:
            # Unlock account automatically after lockout period
            self.failed_login_attempts = 0
            self.account_locked_until = None
            db.session.commit()
        return False
    
    def record_failed_login(self, max_attempts=5, lockout_duration=900):
        """Record failed login attempt and lock account if threshold exceeded"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.account_locked_until = datetime.utcnow() + timedelta(seconds=lockout_duration)
        db.session.commit()
    
    def record_successful_login(self):
        """Reset failed attempts and update last login time"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def has_role(self, role):
        """Check if user has specific role"""
        return self.role == role
    
    def can_review_loans(self):
        """Check if user can review loan applications"""
        return self.role in ['loan_officer', 'manager']
    
    def can_approve_loans(self):
        """Check if user can approve loans (managers only)"""
        return self.role == 'manager'
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Loan(db.Model):
    """
    Loan application model with workflow states
    """
    __tablename__ = 'loans'
    
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Loan Details
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    duration_months = db.Column(db.Integer, nullable=False)
    
    # Workflow State
    status = db.Column(db.String(20), default='pending', nullable=False)
    # Status: pending -> under_review -> approved/rejected
    
    # Assignment
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Review/Approval Data
    review_notes = db.Column(db.Text, nullable=True)
    review_date = db.Column(db.DateTime, nullable=True)
    approval_notes = db.Column(db.Text, nullable=True)
    approval_date = db.Column(db.DateTime, nullable=True)
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    documents = db.relationship('Document', backref='loan', lazy='dynamic', cascade='all, delete-orphan')
    reviewed_by = db.relationship('User', foreign_keys=[reviewed_by_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])
    
    def can_be_viewed_by(self, user):
        """Check if user can view this loan application"""
        # Member can only view their own loans
        if user.role == 'member':
            return self.member_id == user.id
        # Officers and managers can view all loans
        return user.role in ['loan_officer', 'manager']
    
    def can_be_edited_by(self, user):
        """Check if user can edit this loan"""
        # Only the applicant can edit, and only if status is pending
        return self.member_id == user.id and self.status == 'pending'
    
    def can_be_reviewed_by(self, user):
        """Check if user can review this loan"""
        # Loan officers can review pending loans
        return user.role == 'loan_officer' and self.status == 'pending'
    
    def can_be_approved_by(self, user):
        """Check if user can approve this loan"""
        # Managers can approve reviewed loans
        # Loan officers cannot approve (separation of duties)
        return user.role == 'manager' and self.status == 'under_review'
    
    def __repr__(self):
        return f'<Loan {self.id} - {self.status}>'


class Document(db.Model):
    """
    Document model for loan supporting documents
    """
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loans.id'), nullable=False, index=True)
    
    # File Information
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    
    # Metadata
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])
    
    def can_be_viewed_by(self, user):
        """Check if user can view this document"""
        # Same access control as parent loan
        return self.loan.can_be_viewed_by(user)
    
    def __repr__(self):
        return f'<Document {self.original_filename}>'


class AuditLog(db.Model):
    """
    Audit log for security-sensitive operations
    """
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Event Information
    event_type = db.Column(db.String(50), nullable=False, index=True)
    # Event types: login, logout, login_failed, loan_created, loan_reviewed, 
    # loan_approved, loan_rejected, document_uploaded, document_viewed, etc.
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=True)
    
    # Request Context
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.String(500), nullable=True)
    
    # Event Details
    resource_type = db.Column(db.String(50), nullable=True)  # loan, document, user
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON or text description
    
    # Result
    success = db.Column(db.Boolean, default=True, nullable=False)
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationship
    user = db.relationship('User', foreign_keys=[user_id])
    
    def __repr__(self):
        return f'<AuditLog {self.event_type} by {self.username} at {self.timestamp}>'
