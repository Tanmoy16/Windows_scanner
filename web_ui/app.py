# web_ui/app.py
import sys
import os
from flask import Flask, render_template, request, url_for

# Add the root directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from scanner.integration import run_scan

app = Flask(__name__)

@app.route('/')
def get_started():
    """Renders the initial 'Get Started' page."""
    return render_template('get_started.html')

@app.route('/loader')
def loader():
    """Renders the loading animation page."""
    return render_template('loader.html')

@app.route('/dashboard')
def index():
    """Renders the main dashboard page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handles the form submission and displays results."""
    targets = request.form.get('targets')
    profile = request.form.get('profile')
    custom_ports = request.form.get('ports')
    
    results = run_scan(
        targets=targets,
        profile=profile,
        custom_ports=custom_ports
    )
    
    return render_template('results.html', results=results, target=targets)

if __name__ == '__main__':
    app.run(debug=True)