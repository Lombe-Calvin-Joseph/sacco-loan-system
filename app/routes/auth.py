"""
Authentication Routes - Login, Registration, Logout
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from app import db
from app.models import User
from app.forms.auth_forms import LoginForm, RegistrationForm
from app.utils.audit import log_security_event, log_login_attempt

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login with account lockout protection"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user is None:
            # Don't reveal whether user exists
            log_login_attempt(form.username.data, False, "User not found")
            flash('Invalid username or password.', 'danger')
            return render_template('auth/login.html', form=form)
        
        # Check if account is locked
        if user.is_account_locked():
            log_login_attempt(user.username, False, "Account locked")
            flash('Account temporarily locked due to multiple failed login attempts. Please try again later.', 'danger')
            return render_template('auth/login.html', form=form)
        
        # Check if account is active
        if not user.is_active:
            log_login_attempt(user.username, False, "Account deactivated")
            flash('Your account has been deactivated. Please contact support.', 'danger')
            return render_template('auth/login.html', form=form)
        
        # Verify password
        if not user.check_password(form.password.data):
            user.record_failed_login(max_attempts=5, lockout_duration=900)
            log_login_attempt(user.username, False, "Invalid password")
            flash('Invalid username or password.', 'danger')
            return render_template('auth/login.html', form=form)
        
        # Successful login
        user.record_successful_login()
        login_user(user, remember=False)  # Session-based, no "remember me"
        log_login_attempt(user.username, True)
        
        # Redirect to appropriate dashboard
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('main.dashboard')
        
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(next_page)
    
    return render_template('auth/login.html', form=form)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with password policy enforcement"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            is_active=True
        )
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            log_security_event(
                event_type='user_registered',
                resource_type='user',
                resource_id=user.id,
                details=f'New user registered: {user.username} ({user.role})',
                user=None
            )
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            print(f"Registration error: {str(e)}")
    
    return render_template('auth/register.html', form=form)


@bp.route('/logout')
def logout():
    """User logout with audit logging"""
    if current_user.is_authenticated:
        log_security_event(
            event_type='logout',
            details=f'User {current_user.username} logged out'
        )
        logout_user()
    
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
