# web_ui/app.py

import sys
import os
from flask import Flask, render_template, request

# This is a crucial step to make the 'scanner' module importable
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from scanner.integration import run_scan

app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

@app.route('/')
def index():
    """Renders the main homepage with the scan form."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handles the form submission, runs the scan, and displays results."""
    # Get data directly from the submitted form
    targets = request.form.get('targets')
    profile = request.form.get('profile')
    custom_ports = request.form.get('ports')
    username = request.form.get('user')
    password = request.form.get('password')

    # Run the scanner function
    results = run_scan(
        targets=targets,
        profile=profile,
        custom_ports=custom_ports,
        username=username,
        password=password
    )

    # Render the results page, passing the results data to the template
    return render_template('results.html', results=results, target=targets)

if __name__ == '__main__':
    app.run(debug=True)