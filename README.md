# 🔒 WinScan Pro  
**Agentless Windows Vulnerability Scanner with Web UI**  

---

## 🚩 Overview  
Most security scanners require heavy agents, are expensive, or are hard to integrate.  
We built **WinScan Pro** as a **lightweight, agentless vulnerability scanner** that:  
- Scans **Windows machines** over SMB/WinRM without installing agents.  
- Detects **open ports, weak configurations, and common vulnerabilities**.  
- Offers both **safe scans** (top 1000 ports) and **deep scans** (custom ports).  
- Provides a **simple Web UI** along with automated downloadable HTML reports.  

---

## 🛠️ Tech Stack  
- **Backend**: Python (Flask)  
- **Frontend**: HTML, CSS, vanilla JS  
- **Scanner Core**: Native Python Socket module (no external Nmap dependency!)  
- **Database**: MongoDB (Local)  

---

## 📋 Prerequisites
To run this project on your local system, you need the following installed:
1. **Python 3.10+**: Download from [python.org](https://www.python.org/downloads/)
2. **MongoDB Community Server**: Download from [mongodb.com](https://www.mongodb.com/try/download/community)

*(Ensure the MongoDB service, `mongod`, is running on its default port `27017` on your system).*

---

## 🚀 Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/Tanmoy16/Windows_scanner.git
cd Windows_scanner
```

**2. Create a virtual environment (Recommended)**
```bash
python -m venv .venv
```
**Activate it:**
- On **Windows**: `.venv\Scripts\activate`
- On **Linux/Mac**: `source .venv/bin/activate`

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Verify MongoDB Connection**
Run the included helper script to test the database and create collections:
```bash
python setup_mongodb.py
```

---

## ⚡ Running the Application

1. Open your terminal in the project directory (ensure your virtual environment is active).
2. Start the Flask application:
   ```bash
   python web_ui/app.py
   ```
3. Open a web browser and navigate to: **[http://localhost:5000](http://localhost:5000)**

*Note: The project includes an email-based authentication system. To use the password reset and email reports features fully, you'll need to update the `MAIL_USERNAME` and `MAIL_PASSWORD` variables in `web_ui/app.py` with your own SMTP credentials.*

---

## 🐳 Docker Deployment
You can build a lightweight Docker image for deployment:
```bash
docker build -t winscan-pro .
docker run -p 10000:10000 winscan-pro
```
*(Make sure to update the `MONGO_URI` in `app.py` to point to a valid Mongo container network if running in a pure Docker environment).*

---

## 🎯 Future Scope  
- Add **CVE Database Integration** mapping.  
- Bring Role-Based Access Control (RBAC).  
- Enterprise cloud deployment support.

---

*Disclaimer: For educational and authorized auditing purposes only.*
