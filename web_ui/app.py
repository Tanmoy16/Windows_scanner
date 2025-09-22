# web_ui/app.py

import sys
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for

# Add the root directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from scanner.integration import run_scan

app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

# Ensure the reports directory exists
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route('/')
def dashboard():
    """Renders the main dashboard page."""
    # For a real app, you might pass stats here
    return render_template('dashboard.html')

@app.route('/new_scan')
def new_scan():
    """Renders the page with the new scan form."""
    return render_template('new_scan.html')

@app.route('/run_scan', methods=['POST'])
def run_scan_route():
    """Handles the form submission, runs the scan, saves the report, and redirects to results."""
    targets = request.form.get('targets')
    profile = request.form.get('profile')
    custom_ports = request.form.get('ports')
    
    # Run the actual scanner
    results = run_scan(
        targets=targets,
        profile=profile,
        custom_ports=custom_ports
    )
    
    # --- New Feature: Save the report ---
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"scan_report_{timestamp}.json"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    report_data = {
        "target": targets,
        "profile": profile,
        "timestamp": timestamp.replace("_", " "),
        "results": results
    }
    
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    # Redirect to the page that displays this new report
    return redirect(url_for('view_report', filename=report_filename))

@app.route('/reports')
def reports():
    """Renders the list of all saved scan reports."""
    report_files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return render_template('reports.html', reports=report_files)

@app.route('/report/<filename>')
def view_report(filename):
    """Renders the results from a specific saved report file."""
    report_path = os.path.join(REPORTS_DIR, filename)
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        return render_template('results.html', data=data)
    except FileNotFoundError:
        return "Report not found", 404

if __name__ == '__main__':
    app.run(debug=True)