"""
Application Factory with Security Controls
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config.config import config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def create_app(config_name=None):
    """
    Application factory with security configuration
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Ensure logs directory exists
    log_dir = os.path.dirname(app.config['LOG_FILE'])
    os.makedirs(log_dir, exist_ok=True)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    # Configure Flask-Login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.session_protection = 'strong'  # Detect session hijacking
    
    # Configure logging
    setup_logging(app)
    
    # Register security middleware
    register_security_middleware(app)
    
    # Register blueprints
    from app.routes import auth, member, loan_officer, manager, main
    app.register_blueprint(auth.bp)
    app.register_blueprint(member.bp)
    app.register_blueprint(loan_officer.bp)
    app.register_blueprint(manager.bp)
    app.register_blueprint(main.bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app


def setup_logging(app):
    """Configure application logging"""
    if not app.debug and not app.testing:
        # File handler
        file_handler = RotatingFileHandler(
            app.config['LOG_FILE'],
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
        ))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.info('SACCO Loan Application startup')


def register_security_middleware(app):
    """Register security-related middleware and hooks"""
    
    @app.after_request
    def set_security_headers(response):
        """Add security headers to all responses"""
        for header, value in app.config['SECURITY_HEADERS'].items():
            response.headers[header] = value
        return response
    
    @app.after_request
    def log_request(response):
        """Log all requests for audit purposes"""
        if not app.testing:
            app.logger.info(
                f'{request.remote_addr} - {request.method} {request.path} - {response.status_code}'
            )
        return response
    
    @login_manager.user_loader
    def load_user(user_id):
        """Load user for Flask-Login"""
        from app.models import User
        return User.query.get(int(user_id))
    
    @login_manager.unauthorized_handler
    def unauthorized():
        """Handle unauthorized access attempts"""
        from flask import flash, redirect, url_for
        from app.utils.audit import log_security_event
        
        log_security_event(
            event_type='unauthorized_access',
            details=f'Attempted access to {request.path}',
            success=False
        )
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('auth.login'))
