"""
Loan Application Forms with CSRF Protection and Validation
"""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import DecimalField, IntegerField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Length, ValidationError
from app.utils.validators import validate_loan_amount, validate_duration


class LoanApplicationForm(FlaskForm):
    """Loan application form with input validation"""
    amount = DecimalField('Loan Amount (ZMW)', 
                         validators=[DataRequired(), NumberRange(min=0.01, max=1000000)],
                         places=2)
    purpose = TextAreaField('Purpose of Loan', 
                           validators=[DataRequired(), Length(min=10, max=1000)])
    duration_months = IntegerField('Duration (Months)', 
                                  validators=[DataRequired(), NumberRange(min=1, max=120)])
    submit = SubmitField('Submit Application')
    
    def validate_amount(self, field):
        """Custom validator for loan amount"""
        is_valid, error_msg = validate_loan_amount(field.data)
        if not is_valid:
            raise ValidationError(error_msg)
    
    def validate_duration_months(self, field):
        """Custom validator for duration"""
        is_valid, error_msg = validate_duration(field.data)
        if not is_valid:
            raise ValidationError(error_msg)


class DocumentUploadForm(FlaskForm):
    """Document upload form with file validation"""
    document = FileField('Supporting Document', 
                        validators=[
                            DataRequired(),
                            FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 
                                      'Only PDF and image files are allowed')
                        ])
    submit = SubmitField('Upload Document')


class LoanReviewForm(FlaskForm):
    """Loan review form for loan officers"""
    review_notes = TextAreaField('Review Notes', 
                                validators=[DataRequired(), Length(min=10, max=2000)])
    submit = SubmitField('Submit Review')


class LoanApprovalForm(FlaskForm):
    """Loan approval form for managers"""
    approval_notes = TextAreaField('Approval/Rejection Notes', 
                                  validators=[DataRequired(), Length(min=10, max=2000)])
    approve = SubmitField('Approve Loan')
    reject = SubmitField('Reject Loan')
