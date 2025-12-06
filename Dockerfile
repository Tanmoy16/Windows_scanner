# Use a lightweight Python image
FROM python:3.10-slim

# 1. Install Nmap (Required for the scanner to work)
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# 2. Copy requirements and install Python libraries
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn  # Install production server

# 3. Copy the rest of your application code
COPY . .

# 4. Run the application using Gunicorn
# 'web_ui.app:app' means: look in folder 'web_ui', file 'app.py', for the object 'app'
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "web_ui.app:app"]