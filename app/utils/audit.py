"""
Audit Logging Utilities - Security event tracking
"""
from datetime import datetime
from flask import request
from flask_login import current_user
from app.models import AuditLog
from app import db


def log_security_event(event_type, resource_type=None, resource_id=None, 
                       details=None, success=True, user=None):
    """
    Log a security-relevant event to the audit log
    
    Args:
        event_type: Type of event (login, logout, loan_created, etc.)
        resource_type: Type of resource affected (loan, document, user)
        resource_id: ID of the affected resource
        details: Additional details about the event
        success: Whether the operation was successful
        user: User object (defaults to current_user)
    """
    try:
        if user is None:
            user = current_user if current_user.is_authenticated else None
        
        log_entry = AuditLog(
            event_type=event_type,
            user_id=user.id if user else None,
            username=user.username if user else 'anonymous',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent', '')[:500] if request else None,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            success=success,
            timestamp=datetime.utcnow()
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
    except Exception as e:
        # Don't let audit logging failures break the application
        db.session.rollback()
        print(f"Audit logging failed: {str(e)}")


def log_login_attempt(username, success, reason=None):
    """Log a login attempt"""
    log_security_event(
        event_type='login_success' if success else 'login_failed',
        details=f"Username: {username}" + (f" - {reason}" if reason else ""),
        success=success,
        user=None  # User not authenticated yet
    )


def log_loan_action(action, loan, details=None):
    """
    Log an action on a loan application
    
    Args:
        action: created, updated, reviewed, approved, rejected
        loan: Loan object
        details: Additional details
    """
    log_security_event(
        event_type=f'loan_{action}',
        resource_type='loan',
        resource_id=loan.id,
        details=details or f'Loan {loan.id} {action}'
    )


def log_document_action(action, document, details=None):
    """
    Log an action on a document
    
    Args:
        action: uploaded, viewed, downloaded, deleted
        document: Document object
        details: Additional details
    """
    log_security_event(
        event_type=f'document_{action}',
        resource_type='document',
        resource_id=document.id,
        details=details or f'Document {document.original_filename} {action}'
    )


def log_access_denied(resource_type, resource_id, reason):
    """Log an access denial"""
    log_security_event(
        event_type='access_denied',
        resource_type=resource_type,
        resource_id=resource_id,
        details=reason,
        success=False
    )


def get_recent_audit_logs(limit=100, event_type=None, user_id=None):
    """
    Retrieve recent audit logs with optional filtering
    
    Args:
        limit: Maximum number of logs to return
        event_type: Filter by event type
        user_id: Filter by user ID
    
    Returns:
        List of AuditLog objects
    """
    query = AuditLog.query
    
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
