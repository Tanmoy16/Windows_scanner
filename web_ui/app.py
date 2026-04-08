import sys
import os
import json
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer

# --- PATH SETUP ---
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from scanner.integration import run_scan

# --- APP CONFIGURATION ---
app = Flask(__name__)
app.secret_key = '018b3d6faba6dcb78297b8721c5f3a09b45db71e98d' # Cryptographically strong static key 

# MongoDB Config (Local MongoDB)
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/winscan_db")
mongo = PyMongo(app)


# Rate Limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"])

# Mail Configuration (Placeholder - User must change these)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'winscan.pro@gmail.com' 
app.config['MAIL_PASSWORD'] = 'doajcmiykjszmvxh'    
app.config['MAIL_DEFAULT_SENDER'] = 'winscan.pro@gmail.com' 
mail = Mail(app)

# Email verification serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# --- USER MODEL WRAPPER ---
# Flask-Login needs a class, so we wrap the MongoDB dictionary
class User(UserMixin):
    def __init__(self, user_dict):
        self.id = str(user_dict.get('_id'))
        self.username = user_dict.get('username')
        self.email = user_dict.get('email')
        self.password = user_dict.get('password')
        self.is_verified = user_dict.get('is_verified', False)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

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

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        identifier = request.form.get('username_or_email')
        password = request.form.get('password')
        
        user_data = mongo.db.users.find_one({
            "$or": [{"username": identifier}, {"email": identifier}]
        })
        
        if user_data and check_password_hash(user_data['password'], password):
            if not user_data.get('is_verified', False):
                flash('Please confirm your email address first. Check your inbox.', 'error')
                return redirect(url_for('login'))
                
            user_obj = User(user_data)
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if mongo.db.users.find_one({"$or": [{"username": username}, {"email": email}]}):
            flash('Username or Email already exists.', 'error')
            return redirect(url_for('register'))
            
        hashed_pw = generate_password_hash(password)
        
        # Insert into MongoDB
        result = mongo.db.users.insert_one({"username": username, "email": email, "password": hashed_pw, "is_verified": False})
        
        # Send verification email
        token = serializer.dumps(email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        
        msg = Message("Confirm your WinScan Pro Account", recipients=[email])
        msg.html = f"<p>Welcome to WinScan Pro!</p><p>Please verify your account by clicking the link below:</p><p><a href='{confirm_url}'>Verify Your Account</a></p>"
        
        try:
            mail.send(msg)
            flash('A confirmation email has been sent to your address. Please check your inbox.', 'success')
        except Exception as e:
            flash('Account created, but failed to send verification email. SMTP may not be configured.', 'error')
            print(f"Error sending email: {e}")
            
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
        
    user = mongo.db.users.find_one({"email": email})
    if user:
        if user.get("is_verified"):
            flash('Account already verified. Please login.', 'success')
        else:
            mongo.db.users.update_one({"email": email}, {"$set": {"is_verified": True}})
            flash('You have verified your account. Thanks!', 'success')
    return redirect(url_for('login'))

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
    # Fetch user reports sorted by newest first
    user_reports = list(mongo.db.reports.find({"user_id": current_user.id}).sort("timestamp", -1))
    
    clean_reports = []
    for r in user_reports:
        clean_reports.append({
            "id": str(r["_id"]),
            "scan_id": r["scan_id"],
            "target": r["target"],
            "timestamp": r["timestamp"].strftime('%Y-%m-%d %H:%M:%S'),
            "summary": {
                "critical": r["summary_critical"],
                "medium": r["summary_medium"],
                "hosts_scanned": 1
            }
        })

    stats = {
        "total_scans": len(user_reports),
        "critical_issues": sum(r["summary_critical"] for r in user_reports),
        "medium_issues": sum(r["summary_medium"] for r in user_reports)
    }
    
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
@limiter.limit("5 per minute")
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

    config = load_config()
    real_results = run_scan(targets, profile, custom_ports, username, password, enabled_plugins=config)

    crit_count = sum(1 for r in real_results if r.get('severity') == 'Critical')
    med_count = sum(1 for r in real_results if r.get('severity') == 'Medium')
    
    # Store directly in MongoDB as a dictionary
    new_report = {
        "scan_id": f"SC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "target": targets,
        "timestamp": datetime.now(),
        "summary_critical": crit_count,
        "summary_medium": med_count,
        "full_json": real_results,
        "user_id": current_user.id
    }
    
    result = mongo.db.reports.insert_one(new_report)
    
    # --- Send HTML Email Report ---
    if current_user.email:
        try:
            data = {
                "scan_id": new_report["scan_id"],
                "target": targets,
                "results": real_results,
                "summary": { "critical": crit_count, "medium": med_count }
            }
            msg = Message(f"WinScan Pro Report: {new_report['scan_id']}", recipients=[current_user.email])
            # Render the same exact HTML template we use for the web view
            msg.html = render_template('results.html', data=data) 
            mail.send(msg)
            print(f"[+] Sent report email to {current_user.email}")
        except Exception as e:
            print(f"[!] Failed to send report email: {e}")
            
    return redirect(url_for('view_report', id=str(result.inserted_id)))

@app.route('/reports')
@login_required
def reports():
    user_reports = list(mongo.db.reports.find({"user_id": current_user.id}))
    all_vulnerabilities = []
    
    for report in user_reports:
        # No more json.loads() needed!
        for res in report["full_json"]:
            if res.get('status') == 'FAIL':
                v = res.copy()
                v['report_id'] = str(report['_id'])
                all_vulnerabilities.append(v)
                
    return render_template('reports.html', vulnerabilities=all_vulnerabilities)

# Notice we changed <int:id> to <id> because MongoDB ObjectIds are strings in URLs
@app.route('/report/<id>') 
@login_required
def view_report(id):
    try:
        report = mongo.db.reports.find_one({"_id": ObjectId(id), "user_id": current_user.id})
    except:
        abort(404)
        
    if not report:
        abort(404)
        
    data = {
        "scan_id": report["scan_id"],
        "target": report["target"],
        "results": report["full_json"],
        "summary": { "critical": report["summary_critical"], "medium": report["summary_medium"] }
    }
    return render_template('results.html', data=data, report_id=str(report["_id"]))



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)