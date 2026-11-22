"""
SACCO Loan Application System - Main Entry Point
"""
import os
from app import create_app, db
from app.models import User, Loan, Document, AuditLog

# Create application instance
app = create_app(os.environ.get('FLASK_ENV', 'development'))


@app.shell_context_processor
def make_shell_context():
    """Make database models available in Flask shell"""
    return {
        'db': db,
        'User': User,
        'Loan': Loan,
        'Document': Document,
        'AuditLog': AuditLog
    }


@app.cli.command()
def init_db():
    """Initialize the database with sample data"""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
        
        # Check if users already exist
        if User.query.first():
            print("Database already contains data. Skipping sample data creation.")
            return
        
        # Create sample users
        print("Creating sample users...")
        
        # Member
        member = User(username='john_member', email='john@example.com', role='member', is_active=True)
        member.set_password('Password123!')
        db.session.add(member)
        
        # Loan Officer
        officer = User(username='sarah_officer', email='sarah@example.com', role='loan_officer', is_active=True)
        officer.set_password('Password123!')
        db.session.add(officer)
        
        # Manager
        manager = User(username='mike_manager', email='mike@example.com', role='manager', is_active=True)
        manager.set_password('Password123!')
        db.session.add(manager)
        
        db.session.commit()
        print("Sample users created:")
        print("  Member: john_member / Password123!")
        print("  Loan Officer: sarah_officer / Password123!")
        print("  Manager: mike_manager / Password123!")


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
