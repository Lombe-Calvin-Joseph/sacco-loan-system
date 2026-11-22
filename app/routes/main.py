"""
Main Routes - Dashboard and common pages
"""
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    """
    Role-based dashboard redirect
    Each role gets their own dashboard view
    """
    if current_user.role == 'member':
        return redirect(url_for('member.dashboard'))
    elif current_user.role == 'loan_officer':
        return redirect(url_for('loan_officer.dashboard'))
    elif current_user.role == 'manager':
        return redirect(url_for('manager.dashboard'))
    else:
        return render_template('error.html', message='Invalid user role'), 403
