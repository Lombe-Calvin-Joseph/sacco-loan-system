"""
Member Routes - Loan applications and document uploads
"""
import os
import uuid
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import Loan, Document
from app.forms.loan_forms import LoanApplicationForm, DocumentUploadForm
from app.utils.decorators import role_required, check_account_status
from app.utils.validators import validate_file_upload, sanitize_text_input
from app.utils.audit import log_loan_action, log_document_action, log_access_denied

bp = Blueprint('member', __name__, url_prefix='/member')


@bp.route('/dashboard')
@login_required
@role_required('member')
@check_account_status
def dashboard():
    """Member dashboard showing their loan applications"""
    # Only show loans belonging to current user
    loans = Loan.query.filter_by(member_id=current_user.id)\
                     .order_by(Loan.created_at.desc())\
                     .all()
    
    return render_template('member/dashboard.html', loans=loans)


@bp.route('/loan/apply', methods=['GET', 'POST'])
@login_required
@role_required('member')
@check_account_status
def apply_loan():
    """Submit a new loan application"""
    form = LoanApplicationForm()
    
    if form.validate_on_submit():
        # Sanitize text inputs
        purpose = sanitize_text_input(form.purpose.data, max_length=1000)
        
        # Create loan application
        loan = Loan(
            member_id=current_user.id,
            amount=form.amount.data,
            purpose=purpose,
            duration_months=form.duration_months.data,
            status='pending'
        )
        
        try:
            db.session.add(loan)
            db.session.commit()
            
            log_loan_action('created', loan, f'Amount: {loan.amount}, Duration: {loan.duration_months} months')
            
            flash('Loan application submitted successfully!', 'success')
            return redirect(url_for('member.view_loan', loan_id=loan.id))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your application. Please try again.', 'danger')
            print(f"Loan creation error: {str(e)}")
    
    return render_template('member/apply_loan.html', form=form)


@bp.route('/loan/<int:loan_id>')
@login_required
@role_required('member')
@check_account_status
def view_loan(loan_id):
    """View loan application details"""
    loan = Loan.query.get_or_404(loan_id)
    
    # Access control: members can only view their own loans
    if not loan.can_be_viewed_by(current_user):
        log_access_denied('loan', loan_id, 'User does not own this loan')
        flash('You do not have permission to view this loan.', 'danger')
        abort(403)
    
    return render_template('member/view_loan.html', loan=loan)


@bp.route('/loan/<int:loan_id>/upload', methods=['GET', 'POST'])
@login_required
@role_required('member')
@check_account_status
def upload_document(loan_id):
    """Upload supporting documents for a loan application"""
    loan = Loan.query.get_or_404(loan_id)
    
    # Access control: members can only upload to their own loans
    if not loan.can_be_edited_by(current_user):
        log_access_denied('loan', loan_id, 'User cannot edit this loan')
        flash('You cannot upload documents to this loan.', 'danger')
        abort(403)
    
    form = DocumentUploadForm()
    
    if form.validate_on_submit():
        file = request.files.get('document')
        
        # Validate file upload
        is_valid, error_msg, filename = validate_file_upload(
            file,
            allowed_extensions={'pdf', 'jpg', 'jpeg', 'png'},
            max_size=5 * 1024 * 1024  # 5MB
        )
        
        if not is_valid:
            flash(error_msg, 'danger')
            return render_template('member/upload_document.html', loan=loan, form=form)
        
        # Generate unique filename to prevent collisions and path traversal
        file_ext = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
        
        # Create user-specific subdirectory
        user_upload_dir = os.path.join('app', 'static', 'uploads', str(current_user.id))
        os.makedirs(user_upload_dir, exist_ok=True)
        
        file_path = os.path.join(user_upload_dir, unique_filename)
        
        try:
            # Save file
            file.save(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Create document record
            document = Document(
                loan_id=loan.id,
                filename=unique_filename,
                original_filename=secure_filename(file.filename),
                file_path=file_path,
                file_size=file_size,
                mime_type=file.content_type or 'application/octet-stream',
                uploaded_by_id=current_user.id
            )
            
            db.session.add(document)
            db.session.commit()
            
            log_document_action('uploaded', document, f'Loan ID: {loan.id}')
            
            flash('Document uploaded successfully!', 'success')
            return redirect(url_for('member.view_loan', loan_id=loan.id))
            
        except Exception as e:
            db.session.rollback()
            # Clean up file if database operation fails
            if os.path.exists(file_path):
                os.remove(file_path)
            flash('An error occurred while uploading the document. Please try again.', 'danger')
            print(f"Document upload error: {str(e)}")
    
    return render_template('member/upload_document.html', loan=loan, form=form)


@bp.route('/document/<int:document_id>/download')
@login_required
@role_required('member')
@check_account_status
def download_document(document_id):
    """Download a document (with access control)"""
    document = Document.query.get_or_404(document_id)
    
    # Access control: check if user can view the parent loan
    if not document.can_be_viewed_by(current_user):
        log_access_denied('document', document_id, 'User cannot access this document')
        flash('You do not have permission to access this document.', 'danger')
        abort(403)
    
    # Verify file exists
    if not os.path.exists(document.file_path):
        flash('Document file not found.', 'danger')
        abort(404)
    
    log_document_action('downloaded', document)
    
    return send_file(
        document.file_path,
        as_attachment=True,
        download_name=document.original_filename,
        mimetype=document.mime_type
    )
