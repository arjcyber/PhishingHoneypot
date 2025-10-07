from flask import Blueprint, render_template, send_from_directory
from ndaill.engine import generate_fake_admin_panel, get_flagged_logs, audit_clearance
import os

# ✅ Blueprint name matches what app.py expects
ndaill_bp = Blueprint('ndaill', __name__, template_folder='../templates/ndaill', static_folder='../static/ndaill')

@ndaill_bp.route('/')
def dashboard():
    return render_template('ndaill/fake_admin.html')


@ndaill_bp.route('/leaked_keys')
def leaked_keys():
    return render_template('ndaill/leaked_keys.html')

@ndaill_bp.route('/static/fake_keys.txt')
def leaked_keys_file():
    # ✅ Sends file from static/ndaill/fake_keys.txt
    return send_from_directory(os.path.join('static', 'ndaill'), 'fake_keys.txt')

@ndaill_bp.route('/flagged')
def flagged():
    data = get_flagged_logs()
    return render_template('ndaill/flagged_access.html', flagged=data)

@ndaill_bp.route('/clearance')
def clearance():
    logs = audit_clearance()
    return render_template('ndaill/clearance_audit.html', logs=logs)
