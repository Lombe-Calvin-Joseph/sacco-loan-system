"""
Manager Routes - Approve/reject reviewed loan applications
"""
import os
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_required, current_user
from app import db
from app.models import Loan, Document, AuditLog
from app.forms.loan_forms import LoanApprovalForm
from app.utils.decorators import role_required, check_account_status
from app.utils.validators import sanitize_text_input
from app.utils.audit import log_loan_action, log_document_action, log_access_denied, get_recent_audit_logs

bp = Blueprint('manager', __name__, url_prefix='/manager')


@bp.route('/dashboard')
@login_required
@role_required('manager')
@check_account_status
def dashboard():
    """Manager dashboard showing loans requiring approval"""
    # Show loans under review (ready for approval)
    under_review_loans = Loan.query.filter_by(status='under_review')\
                                  .order_by(Loan.review_date.asc())\
                                  .all()
    
    # Show recently processed loans
    processed_loans = Loan.query.filter(Loan.status.in_(['approved', 'rejected']))\
                               .order_by(Loan.approval_date.desc())\
                               .limit(20)\
                               .all()
    
    # Get summary statistics
    total_pending = Loan.query.filter_by(status='pending').count()
    total_under_review = len(under_review_loans)
    total_approved = Loan.query.filter_by(status='approved').count()
    total_rejected = Loan.query.filter_by(status='rejected').count()
    
    stats = {
        'pending': total_pending,
        'under_review': total_under_review,
        'approved': total_approved,
        'rejected': total_rejected
    }
    
    return render_template('manager/dashboard.html',
                          under_review_loans=under_review_loans,
                          processed_loans=processed_loans,
                          stats=stats)


@bp.route('/loan/<int:loan_id>')
@login_required
@role_required('manager')
@check_account_status
def view_loan(loan_id):
    """View loan application details"""
    loan = Loan.query.get_or_404(loan_id)
    
    # Managers can view all loans
    if not loan.can_be_viewed_by(current_user):
        log_access_denied('loan', loan_id, 'Access denied')
        flash('You do not have permission to view this loan.', 'danger')
        abort(403)
    
    return render_template('manager/view_loan.html', loan=loan)


@bp.route('/loan/<int:loan_id>/approve', methods=['GET', 'POST'])
@login_required
@role_required('manager')
@check_account_status
def approve_loan(loan_id):
    """
    Approve or reject a loan application
    Separation of duties: Only managers can approve, not loan officers
    """
    loan = Loan.query.get_or_404(loan_id)
    
    # Access control: managers can only approve loans under review
    if not loan.can_be_approved_by(current_user):
        log_access_denied('loan', loan_id, 'Loan not in approvable state')
        flash('This loan cannot be approved at this time.', 'danger')
        abort(403)
    
    # Additional check: prevent loan officer from approving their own reviewed loans
    # (though they shouldn't have manager role anyway)
    if loan.reviewed_by_id == current_user.id:
        log_access_denied('loan', loan_id, 'Cannot approve own review')
        flash('You cannot approve a loan you reviewed yourself.', 'danger')
        abort(403)
    
    form = LoanApprovalForm()
    
    if form.validate_on_submit():
        # Sanitize input
        approval_notes = sanitize_text_input(form.approval_notes.data, max_length=2000)
        
        # Determine action based on which button was clicked
        if 'approve' in request.form:
            loan.status = 'approved'
            action = 'approved'
            message = 'Loan application approved successfully!'
            flash_category = 'success'
        elif 'reject' in request.form:
            loan.status = 'rejected'
            action = 'rejected'
            message = 'Loan application rejected.'
            flash_category = 'info'
        else:
            flash('Invalid action.', 'danger')
            return render_template('manager/approve_loan.html', loan=loan, form=form)
        
        # Update loan
        loan.approved_by_id = current_user.id
        loan.approval_notes = approval_notes
        loan.approval_date = datetime.utcnow()
        
        try:
            db.session.commit()
            
            log_loan_action(action, loan, 
                          f'{action.capitalize()} by {current_user.username} - Amount: {loan.amount}')
            
            flash(message, flash_category)
            return redirect(url_for('manager.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while processing the loan. Please try again.', 'danger')
            print(f"Loan approval error: {str(e)}")
    
    return render_template('manager/approve_loan.html', loan=loan, form=form)


@bp.route('/document/<int:document_id>/download')
@login_required
@role_required('manager')
@check_account_status
def download_document(document_id):
    """Download a document"""
    document = Document.query.get_or_404(document_id)
    
    # Access control: managers can view all documents
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


@bp.route('/audit-logs')
@login_required
@role_required('manager')
@check_account_status
def audit_logs():
    """View security audit logs (managers only)"""
    # Get filter parameters
    event_type = request.args.get('event_type', None)
    limit = min(int(request.args.get('limit', 100)), 500)  # Cap at 500
    
    # Get audit logs
    logs = get_recent_audit_logs(limit=limit, event_type=event_type)
    
    # Get distinct event types for filter dropdown
    event_types = db.session.query(AuditLog.event_type)\
                           .distinct()\
                           .order_by(AuditLog.event_type)\
                           .all()
    event_types = [et[0] for et in event_types]
    
    return render_template('manager/audit_logs.html', 
                          logs=logs, 
                          event_types=event_types,
                          selected_event_type=event_type)
