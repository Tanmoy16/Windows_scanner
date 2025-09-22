# web_ui/app.py
import sys, os, json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for

# Add the root directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
# from scanner.integration import run_scan # Uncomment when backend is ready

app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

# --- Static page routes for the frontend design ---

@app.route('/')
def get_started():
    return render_template('get_started.html')

@app.route('/loader')
def loader():
    return render_template('loader.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/new_scan')
def new_scan():
    return render_template('new_scan.html')

@app.route('/results')
def results():
    # In a real app, you'd fetch real data here
    return render_template('results.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

# --- Functional route for scanning (placeholder) ---
@app.route('/run_scan', methods=['POST'])
def run_scan_route():
    # This is where your backend logic would run
    # For now, it just redirects to the static results page to show the UI
    return redirect(url_for('results'))

if __name__ == '__main__':
    app.run(debug=True)