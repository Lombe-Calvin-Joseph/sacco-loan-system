"""
Loan Officer Routes - Review loan applications (cannot approve)
"""
import os
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, send_file, abort
from flask_login import login_required, current_user
from app import db
from app.models import Loan, Document
from app.forms.loan_forms import LoanReviewForm
from app.utils.decorators import role_required, check_account_status
from app.utils.validators import sanitize_text_input
from app.utils.audit import log_loan_action, log_document_action, log_access_denied

bp = Blueprint('loan_officer', __name__, url_prefix='/loan_officer')


@bp.route('/dashboard')
@login_required
@role_required('loan_officer')
@check_account_status
def dashboard():
    """Loan officer dashboard showing all loan applications"""
    # Show all loans, grouped by status
    pending_loans = Loan.query.filter_by(status='pending')\
                             .order_by(Loan.created_at.asc())\
                             .all()
    
    under_review_loans = Loan.query.filter_by(status='under_review')\
                                  .order_by(Loan.review_date.desc())\
                                  .all()
    
    processed_loans = Loan.query.filter(Loan.status.in_(['approved', 'rejected']))\
                               .order_by(Loan.updated_at.desc())\
                               .limit(20)\
                               .all()
    
    return render_template('loan_officer/dashboard.html',
                          pending_loans=pending_loans,
                          under_review_loans=under_review_loans,
                          processed_loans=processed_loans)


@bp.route('/loan/<int:loan_id>')
@login_required
@role_required('loan_officer')
@check_account_status
def view_loan(loan_id):
    """View loan application details"""
    loan = Loan.query.get_or_404(loan_id)
    
    # Loan officers can view all loans
    if not loan.can_be_viewed_by(current_user):
        log_access_denied('loan', loan_id, 'Access denied')
        flash('You do not have permission to view this loan.', 'danger')
        abort(403)
    
    return render_template('loan_officer/view_loan.html', loan=loan)


@bp.route('/loan/<int:loan_id>/review', methods=['GET', 'POST'])
@login_required
@role_required('loan_officer')
@check_account_status
def review_loan(loan_id):
    """Review a loan application (move to under_review status)"""
    loan = Loan.query.get_or_404(loan_id)
    
    # Access control: loan officers can only review pending loans
    if not loan.can_be_reviewed_by(current_user):
        log_access_denied('loan', loan_id, 'Loan not in reviewable state')
        flash('This loan cannot be reviewed at this time.', 'danger')
        abort(403)
    
    form = LoanReviewForm()
    
    if form.validate_on_submit():
        # Sanitize input
        review_notes = sanitize_text_input(form.review_notes.data, max_length=2000)
        
        # Update loan status
        loan.status = 'under_review'
        loan.reviewed_by_id = current_user.id
        loan.review_notes = review_notes
        loan.review_date = datetime.utcnow()
        
        try:
            db.session.commit()
            
            log_loan_action('reviewed', loan, f'Reviewed by {current_user.username}')
            
            flash('Loan application reviewed successfully. It is now pending manager approval.', 'success')
            return redirect(url_for('loan_officer.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while reviewing the loan. Please try again.', 'danger')
            print(f"Loan review error: {str(e)}")
    
    return render_template('loan_officer/review_loan.html', loan=loan, form=form)


@bp.route('/document/<int:document_id>/download')
@login_required
@role_required('loan_officer')
@check_account_status
def download_document(document_id):
    """Download a document"""
    document = Document.query.get_or_404(document_id)
    
    # Access control: loan officers can view all documents
    if not document.can_be_viewed_by(current_user):
        log_access_denied('document', document_id, 'Access denied')
        flash('You do not have permission to access this document.', 'danger')
        abort(403)
    
    # Verify file exists
    if not os.path.exists(document.file_path):
        flash('Document file not found.', 'danger')
        abort(404)
    
    log_document_action('viewed', document)
    
    return send_file(
        document.file_path,
        as_attachment=True,
        download_name=document.original_filename,
        mimetype=document.mime_type
    )
