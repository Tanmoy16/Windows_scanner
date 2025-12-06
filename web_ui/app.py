import sys
import os
import json
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- PATH SETUP ---
# Ensure we can find the scanner module
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from scanner.integration import run_scan

# --- APP CONFIGURATION ---
app = Flask(__name__)
app.secret_key = 'winscan_secret_key_change_this' 

# Database Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///winscan.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- CONFIG LOADER ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')

def load_config():
    defaults = {"smb_anon": True, "smb_v1": True, "winrm_hotfix": True, "rdp_open": False, "smb_signing": False}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return {**defaults, **json.load(f)}
        except:
            pass
    return defaults

def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    reports = db.relationship('ScanReport', backref='author', lazy=True)

class ScanReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50))
    target = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    summary_critical = db.Column(db.Integer)
    summary_medium = db.Column(db.Integer)
    full_json = db.Column(db.Text) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
            
        # [FIX] Removed incompatible method='sha256'
        hashed_pw = generate_password_hash(password)
        
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- MAIN ROUTES ---
@app.route('/')
def get_started():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('get_started.html')

# [FIX] Restored missing loader route
@app.route('/loader')
def loader():
    return render_template('loader.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # 1. Get Raw Data from DB
    user_reports = ScanReport.query.filter_by(user_id=current_user.id).order_by(ScanReport.timestamp.desc()).all()
    
    # 2. [CRITICAL FIX] Convert to Dictionary to satisfy HTML template
    clean_reports = []
    for r in user_reports:
        clean_reports.append({
            "id": r.id,
            "scan_id": r.scan_id,
            "target": r.target,
            "timestamp": r.timestamp,
            # We explicitly create the 'summary' object the HTML is looking for
            "summary": {
                "critical": r.summary_critical,
                "medium": r.summary_medium,
                "hosts_scanned": 1
            },
            "filename": r.id # Fallback for old links
        })

    stats = {
        "total_scans": len(user_reports),
        "critical_issues": sum(r.summary_critical for r in user_reports),
        "medium_issues": sum(r.summary_medium for r in user_reports)
    }
    
    # 3. Pass the CLEAN list, NOT the raw 'user_reports'
    return render_template('dashboard.html', stats=stats, recent_scans=clean_reports[:5])

@app.route('/new_scan')
@login_required
def new_scan():
    return render_template('new_scan.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    config = load_config()
    if request.method == 'POST':
        new_config = {
            "smb_anon": request.form.get('smb_anon') == 'on',
            "smb_v1": request.form.get('smb_v1') == 'on',
            "winrm_hotfix": request.form.get('winrm_hotfix') == 'on',
            "rdp_open": request.form.get('rdp_open') == 'on',
            "smb_signing": request.form.get('smb_signing') == 'on'
        }
        save_config(new_config)
        return redirect(url_for('settings'))
    return render_template('settings.html', config=config)

@app.route('/run_scan', methods=['POST'])
@login_required
def run_scan_route():
    targets = request.form.get('targets')
    profile = request.form.get('profile')
    username = request.form.get('username')
    password = request.form.get('password')
    
    custom_ports = None
    if profile == 'deep':
        start_port = request.form.get('start_port')
        end_port = request.form.get('end_port')
        if start_port and end_port:
            custom_ports = f"{start_port}-{end_port}"

    real_results = run_scan(targets, profile, custom_ports, username, password)

    crit_count = sum(1 for r in real_results if r.get('severity') == 'Critical')
    med_count = sum(1 for r in real_results if r.get('severity') == 'Medium')
    
    new_report = ScanReport(
        scan_id=f"SC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        target=targets,
        timestamp=datetime.now(),
        summary_critical=crit_count,
        summary_medium=med_count,
        full_json=json.dumps(real_results),
        author=current_user
    )
    
    db.session.add(new_report)
    db.session.commit()
    
    return redirect(url_for('view_report', id=new_report.id))

@app.route('/reports')
@login_required
def reports():
    user_reports = ScanReport.query.filter_by(user_id=current_user.id).order_by(ScanReport.timestamp.desc()).all()
    all_vulnerabilities = []
    for report in user_reports:
        results = json.loads(report.full_json)
        for res in results:
            if res.get('status') == 'FAIL':
                all_vulnerabilities.append(res)
    return render_template('reports.html', vulnerabilities=all_vulnerabilities)

# [FIX] Route now accepts 'id', matching the database structure
@app.route('/report/<int:id>')
@login_required
def view_report(id):
    report = ScanReport.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    data = {
        "scan_id": report.scan_id,
        "target": report.target,
        "results": json.loads(report.full_json),
        "summary": { "critical": report.summary_critical, "medium": report.summary_medium }
    }
    # Pass 'report_id' so the download button works
    return render_template('results.html', data=data, report_id=report.id)

@app.route('/download/<int:id>')
@login_required
def download_report(id):
    report = ScanReport.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    data = {
        "scan_id": report.scan_id,
        "target": report.target,
        "results": json.loads(report.full_json),
        "summary": { "critical": report.summary_critical, "medium": report.summary_medium }
    }
    html_content = render_template('results.html', data=data)
    fd, path = tempfile.mkstemp(suffix='.html')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True, download_name=f"{report.scan_id}.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)