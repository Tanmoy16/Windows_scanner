# web_ui/app.py
import sys
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for

# Add the root directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
# from scanner.integration import run_scan # This will be used when you connect your backend

app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

def get_all_scan_data():
    """Helper function to read and parse all report files."""
    all_reports = []
    # Ensure we only try to read files that exist
    if not os.path.exists(REPORTS_DIR):
        return all_reports

    for filename in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if filename.endswith(".json"):
            report_path = os.path.join(REPORTS_DIR, filename)
            # --- START OF FIX ---
            # Check if the file is empty before trying to read it
            if os.path.getsize(report_path) == 0:
                print(f"Warning: Skipping empty report file {filename}")
                continue # Skip to the next file
            # --- END OF FIX ---
            try:
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    data['filename'] = filename # Add filename for linking
                    all_reports.append(data)
            except (json.JSONDecodeError, IOError) as e:
                # This will now catch corrupted JSON files and other read errors
                print(f"Warning: Could not read or parse report {filename}: {e}")
    return all_reports

@app.route('/')
def get_started():
    return render_template('get_started.html')

@app.route('/loader')
def loader():
    return render_template('loader.html')

@app.route('/dashboard')
def dashboard():
    """Renders the dashboard with dynamically calculated stats."""
    all_reports = get_all_scan_data()
    
    stats = {
        "total_scans": len(all_reports),
        "hosts_scanned": 0,
        "critical_issues": 0,
        "medium_issues": 0
    }
    
    for report in all_reports:
        stats["hosts_scanned"] += report.get("summary", {}).get("hosts_scanned", 0)
        stats["critical_issues"] += report.get("summary", {}).get("critical", 0)
        stats["medium_issues"] += report.get("summary", {}).get("medium", 0)

    # Get the 5 most recent scans for the activity table
    recent_scans = all_reports[:5]
    
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)


@app.route('/new_scan')
def new_scan():
    return render_template('new_scan.html')

@app.route('/run_scan', methods=['POST'])
def run_scan_route():
    """
    This is a placeholder for your real scan.
    It creates a fake report file to demonstrate the dynamic system.
    """
    # In production, you would replace this with:
    # results = run_scan(...) 
    
    # --- Creating a FAKE report for demonstration ---
    fake_results = [
        {"host": "192.168.1.101", "vulnerability": "SMB Anonymous Access", "status": "FAIL", "severity": "Critical", "plugin": "smb_anon.py"},
        {"host": "192.168.1.105", "vulnerability": "Outdated Windows Updates", "status": "FAIL", "severity": "Medium", "plugin": "win_updates.py"},
    ]
    # --- End of FAKE data ---

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"scan_report_{timestamp}.json"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    report_data = {
        "scan_id": f"SC-{timestamp.replace('_', '-')}",
        "target": request.form.get('targets', 'N/A'),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "hosts_scanned": 12, # Replace with actual count
            "critical": sum(1 for r in fake_results if r['severity'] == 'Critical'),
            "medium": sum(1 for r in fake_results if r['severity'] == 'Medium'),
            "low": sum(1 for r in fake_results if r['severity'] == 'Low'),
        },
        "results": fake_results
    }
    
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    return redirect(url_for('view_report', filename=report_filename))

@app.route('/reports')
def reports():
    """Renders the executive summary report page from all scans."""
    all_reports = get_all_scan_data()
    
    # Extract only critical and medium vulnerabilities for the summary
    key_vulnerabilities = []
    for report in all_reports:
        for vuln in report.get('results', []):
            if vuln['severity'] in ['Critical', 'Medium']:
                key_vulnerabilities.append(vuln)

    return render_template('reports.html', vulnerabilities=key_vulnerabilities)

@app.route('/report/<filename>')
def view_report(filename):
    """Renders the detailed results from a specific report file."""
    report_path = os.path.join(REPORTS_DIR, filename)
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        return render_template('results.html', data=data)
    except (FileNotFoundError, json.JSONDecodeError):
        return "Report not found or is corrupted.", 404