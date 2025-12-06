import sys
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for

# --- Connect the Real Scanner ---
# This adds the project's root directory to the Python path
# so we can import modules from the 'scanner' folder.
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from scanner.integration import run_scan

# --- Flask App Configuration ---
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

# Create a 'reports' directory inside 'web_ui' to save scan results
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

# --- Helper Function to Read Saved Reports ---
def get_all_scan_data():
    """Reads all saved JSON reports from the reports directory."""
    all_reports = []
    if not os.path.exists(REPORTS_DIR):
        return all_reports

    # Sort files by name to show the newest reports first
    for filename in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if filename.endswith(".json"):
            report_path = os.path.join(REPORTS_DIR, filename)
            try:
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    data['filename'] = filename  # Add filename for creating links
                    all_reports.append(data)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not read or parse report file: {filename}")
                continue
    return all_reports

# --- Flask Routes for Your UI ---

@app.route('/')
def get_started():
    """Renders the initial 'Get Started' landing page."""
    return render_template('get_started.html')

@app.route('/loader')
def loader():
    """Renders the loading screen that redirects to the dashboard."""
    return render_template('loader.html')

@app.route('/dashboard')
def dashboard():
    """Displays the main dashboard with aggregated stats and recent scans."""
    all_reports = get_all_scan_data()
    stats = {
        "total_scans": len(all_reports), "hosts_scanned": 0,
        "critical_issues": 0, "medium_issues": 0
    }
    # Aggregate stats from all saved report summaries
    for report in all_reports:
        summary = report.get("summary", {})
        stats["hosts_scanned"] += summary.get("hosts_scanned", 0)
        stats["critical_issues"] += summary.get("critical", 0)
        stats["medium_issues"] += summary.get("medium", 0)

    recent_scans = all_reports[:5]  # Get the 5 most recent scans for the table
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)

@app.route('/new_scan')
def new_scan():
    """Displays the form to start a new vulnerability scan."""
    return render_template('new_scan.html')

@app.route('/run_scan', methods=['POST'])
def run_scan_route():
    """
    Handles the new scan form, calls the real scanner, saves the results,
    and redirects the user to the detailed report page.
    """
    # 1. Get all data from the HTML form in 'new_scan.html'
    targets = request.form.get('targets')
    profile = request.form.get('profile')
    username = request.form.get('username')
    password = request.form.get('password')
    
    custom_ports = None
    if profile == 'deep':
        start_port = request.form.get('start_port')
        end_port = request.form.get('end_port')
        # Nmap can accept a range like "1-1024"
        if start_port and end_port:
            custom_ports = f"{start_port}-{end_port}"
        else:
            return "Error: Deep profile selected but no port range was provided.", 400

    # 2. Call the REAL scanner function from integration.py
    real_results = run_scan(
        targets=targets,
        profile=profile,
        custom_ports=custom_ports,
        username=username,
        password=password
    )

    # 3. Create the report data from the REAL results
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"scan_report_{timestamp}.json"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    # Calculate a real summary from the scanner's output
    summary = {
        "hosts_scanned": len(set(r['host'] for r in real_results if 'host' in r)),
        "critical": sum(1 for r in real_results if r.get('severity') == 'Critical'),
        "high": sum(1 for r in real_results if r.get('severity') == 'High'),
        "medium": sum(1 for r in real_results if r.get('severity') == 'Medium'),
        "low": sum(1 for r in real_results if r.get('severity') == 'Low'),
    }

    report_data = {
        "scan_id": f"SC-{timestamp.replace('_', '-')}",
        "target": targets,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "results": real_results
    }

    # 4. Save the report to a JSON file and redirect to view it
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    return redirect(url_for('view_report', filename=report_filename))

@app.route('/reports')
def reports():
    """Shows a list of all past scan reports."""
    all_reports = get_all_scan_data()
    # The template expects a flat list of all vulnerabilities
    all_vulnerabilities = []
    for report in all_reports:
        for result in report.get("results", []):
            if result.get("status") == "FAIL":
                all_vulnerabilities.append(result)
    return render_template('reports.html', vulnerabilities=all_vulnerabilities)

@app.route('/report/<filename>')
def view_report(filename):
    """Displays the detailed results for a single scan report."""
    report_path = os.path.join(REPORTS_DIR, filename)
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        return render_template('results.html', data=data)
    except (FileNotFoundError, json.JSONDecodeError):
        return "Report not found or is corrupted.", 404

# --- Main execution point ---
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)

