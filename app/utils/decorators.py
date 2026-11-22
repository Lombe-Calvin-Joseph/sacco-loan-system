"""
Security Decorators - Role-based access control and authorization
"""
from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user
from app.utils.audit import log_access_denied


def role_required(*roles):
    """
    Decorator to require specific user roles
    
    Usage:
        @role_required('manager')
        @role_required('loan_officer', 'manager')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            
            if current_user.role not in roles:
                log_access_denied(
                    resource_type='route',
                    resource_id=None,
                    reason=f'User role {current_user.role} not in required roles: {roles}'
                )
                flash('You do not have permission to access this page.', 'danger')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def owns_resource(get_resource_fn, resource_param='id'):
    """
    Decorator to check if current user owns the resource
    
    Args:
        get_resource_fn: Function that takes resource_id and returns the resource
        resource_param: Name of the route parameter containing the resource ID
    
    Usage:
        @owns_resource(lambda id: Loan.query.get_or_404(id), 'loan_id')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            
            resource_id = kwargs.get(resource_param)
            resource = get_resource_fn(resource_id)
            
            # Check if resource has appropriate access control method
            if hasattr(resource, 'can_be_viewed_by'):
                if not resource.can_be_viewed_by(current_user):
                    log_access_denied(
                        resource_type=resource.__class__.__name__.lower(),
                        resource_id=resource_id,
                        reason='User does not have permission to view this resource'
                    )
                    flash('You do not have permission to access this resource.', 'danger')
                    abort(403)
            elif hasattr(resource, 'member_id'):
                # Fallback: check if user owns the resource by member_id
                if resource.member_id != current_user.id and current_user.role == 'member':
                    log_access_denied(
                        resource_type=resource.__class__.__name__.lower(),
                        resource_id=resource_id,
                        reason='User does not own this resource'
                    )
                    flash('You do not have permission to access this resource.', 'danger')
                    abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_account_status(f):
    """
    Decorator to check if user account is active and not locked
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not current_user.is_active:
            flash('Your account has been deactivated. Please contact support.', 'danger')
            return redirect(url_for('auth.logout'))
        
        if current_user.is_account_locked():
            flash('Your account is temporarily locked due to multiple failed login attempts. Please try again later.', 'danger')
            return redirect(url_for('auth.logout'))
        
        return f(*args, **kwargs)
    return decorated_function
