"""
Authentication Forms with CSRF Protection and Validation
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from app.models import User
from app.utils.validators import validate_password, validate_username
from flask import current_app


class LoginForm(FlaskForm):
    """Login form with CSRF protection"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    """User registration form with password policy enforcement"""
    username = StringField('Username', 
                          validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', 
                       validators=[DataRequired(), Email()])
    password = PasswordField('Password', 
                            validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', 
                      choices=[('member', 'Member'), 
                              ('loan_officer', 'Loan Officer'), 
                              ('manager', 'Manager')],
                      validators=[DataRequired()])
    submit = SubmitField('Register')
    
    def validate_username(self, field):
        """Custom validator for username"""
        # Check format
        is_valid, error_msg = validate_username(field.data)
        if not is_valid:
            raise ValidationError(error_msg)
        
        # Check uniqueness
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, field):
        """Custom validator for email"""
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered. Please use a different one.')
    
    def validate_password(self, field):
        """Custom validator for password policy"""
        config = {
            'MIN_PASSWORD_LENGTH': current_app.config['MIN_PASSWORD_LENGTH'],
            'REQUIRE_UPPERCASE': current_app.config['REQUIRE_UPPERCASE'],
            'REQUIRE_LOWERCASE': current_app.config['REQUIRE_LOWERCASE'],
            'REQUIRE_DIGIT': current_app.config['REQUIRE_DIGIT'],
            'REQUIRE_SPECIAL': current_app.config['REQUIRE_SPECIAL']
        }
        
        is_valid, error_msg = validate_password(field.data, config)
        if not is_valid:
            raise ValidationError(error_msg)


class ChangePasswordForm(FlaskForm):
    """Password change form"""
    current_password = PasswordField('Current Password', 
                                    validators=[DataRequired()])
    new_password = PasswordField('New Password', 
                                validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', 
                                    validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')
    
    def validate_new_password(self, field):
        """Custom validator for new password policy"""
        config = {
            'MIN_PASSWORD_LENGTH': current_app.config['MIN_PASSWORD_LENGTH'],
            'REQUIRE_UPPERCASE': current_app.config['REQUIRE_UPPERCASE'],
            'REQUIRE_LOWERCASE': current_app.config['REQUIRE_LOWERCASE'],
            'REQUIRE_DIGIT': current_app.config['REQUIRE_DIGIT'],
            'REQUIRE_SPECIAL': current_app.config['REQUIRE_SPECIAL']
        }
        
        is_valid, error_msg = validate_password(field.data, config)
        if not is_valid:
            raise ValidationError(error_msg)
