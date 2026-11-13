# Intrusion Detection System Using Snort

A complete, production-grade **Network-based Intrusion Detection System (NIDS)** dashboard and Security Operations Center (SOC) portal built using **Snort**, **FastAPI**, **SQLite**, **HTML5/CSS3/JavaScript**, and **Chart.js**.

Designed for Ethical Hacking & Cybersecurity college projects, demonstrations, viva voce defense, and lab simulations.

---

## Key Features

1. **Modern SOC Dashboard (Dark Cyber Theme)**
   - Monitored Packets Counter & Real-Time Anomaly Stream
   - Intrusion counters broken down by Severity (Critical, High, Medium, Low)
   - Visual analytics: Intrusion velocity trend line chart, Protocol doughnut chart, and Top Attack Vectors bar chart
   - Top 5 Threat Source IP tracking

2. **Snort NIDS Integration & Alert Parser**
   - Ingests standard Snort `alert_fast` format logs (`08/21-15:30:00 [**] [1:1000001:1] ...`)
   - Normalizes GID/SID/REV, timestamps, source/destination IP & ports, and protocols
   - Assigns priority-to-severity mappings and classifies attack types

3. **Signature-Based Attack Detection (Configurable Rules)**
   - Pre-configured `local.rules` covering:
     - **ICMP Scanning & Ping Sweeps** (SID 1000001)
     - **Nmap TCP SYN Port Scans** (SID 1000002)
     - **Stealth NULL / Xmas Scans** (SID 1000003, 1000004)
     - **SSH & HTTP Brute-Force Logins** (SID 1000005, 1000006)
     - **Web Application Attacks (SQL Injection / Directory Traversal)** (SID 1000007, 1000008)
     - **DNS Amplification & Anomaly Queries** (SID 1000009)
   - Built-in Snort Rules catalog to add custom signatures and toggle rule active state

4. **Isolated Lab Attack Simulator**
   - One-click trigger buttons to simulate authorized attack traffic vectors for viva demonstrations without requiring external tools
   - Live execution console log

5. **Incident Triage & Status Management**
   - Categorize alerts into **New**, **Investigating**, **False Positive**, or **Resolved**
   - Attach analyst investigation comments and track audit history

6. **Executive Security Reports & PDF Export**
   - Summary of detected threats over 7/14/30-day scopes
   - Automated defensive recommendations (iptables rules, Snort drop signatures, fail2ban setup)
   - Instant downloadable **PDF Security Report** via ReportLab

7. **Role-Based Access Control (RBAC) & Security**
   - Admin (`admin` / `admin123`) & Analyst (`analyst` / `analyst123`) login
   - JWT (JSON Web Token) authentication with bcrypt password hashing
   - Full audit logging for administrative actions

---

## Project Structure

```
Ethical Hacing Project 2/
├── backend/
│   ├── app/
│   │   ├── api/             # API routers (auth, alerts, stats, rules, simulation, reports, audit)
│   │   ├── core/            # Config, security (JWT/bcrypt), database session
│   │   ├── models/          # SQLAlchemy database schemas (User, Alert, SnortRule, AuditLog)
│   │   ├── schemas/         # Pydantic request/response validation schemas
│   │   ├── services/        # Snort log parser, attack simulator, PDF report generator
│   │   └── main.py          # FastAPI application entry point
│   ├── rules/
│   │   └── local.rules      # Custom Snort rule definitions
│   ├── requirements.txt     # Backend Python package requirements
│   └── seed_data.py         # Database initialization and sample data seeder
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── soc_style.css # Modern dark SOC glassmorphism stylesheet
│   │   └── js/              # App logic, Chart.js visualizations, rules & simulator handlers
│   └── templates/           # HTML templates (index, alerts, rules, simulator, reports, login)
├── run.py                   # One-click unified application server launcher
└── README.md                # Project documentation and viva guide
```

---

## Quick Start Guide

### Prerequisites
- Python 3.9+
- Standard Python libraries (`fastapi`, `uvicorn`, `sqlalchemy`, `pydantic`, `reportlab`, `pyjwt`, `bcrypt`)

### Installation & Execution

1. **Navigate to the Project Folder**:
   ```bash
   cd "Ethical Hacing Project 2"
   ```

2. **Install Required Packages** (if not already installed):
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Launch the Application**:
   ```bash
   python run.py
   ```

4. **Access the SOC Dashboard**:
   - Web UI: [http://127.0.0.1:8000](http://127.0.0.1:8000)
   - API Docs (Swagger): [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

5. **Demo Credentials**:
   - **Admin**: Username `admin` | Password `admin123`
   - **Analyst**: Username `analyst` | Password `analyst123`

---

## Real Snort Engine Setup Guide (Optional for Live Linux/Kali Testing)

If you wish to pipe real Snort network alerts from a live network interface into this dashboard on Kali Linux:

1. **Install Snort**:
   ```bash
   sudo apt-get update && sudo apt-get install snort -y
   ```

2. **Configure Local Rules**:
   Copy `backend/rules/local.rules` content into `/etc/snort/rules/local.rules`.

3. **Run Snort in NIDS Alert Mode**:
   ```bash
   sudo snort -A fast -c /etc/snort/snort.conf -i eth0 -l /var/log/snort/
   ```

4. **Connect Log File to Dashboard**:
   Update `SNORT_ALERT_FILE` in `backend/app/core/config.py` to point to `/var/log/snort/snort.alert` (or symbolic link `snort.alert` to your application folder).

---

## Viva Voce Q&A & Project Defense Guide

### Q1: What is Snort and how does signature-based detection work?
**Answer:** Snort is an open-source Network Intrusion Detection System (NIDS) that inspects packet headers and payloads in real time. It uses signature-based detection, comparing incoming traffic against pre-defined rules (such as matching specific byte sequences, TCP flags, or threshold counters) to detect known attack patterns like Nmap scans, SQL injection, or brute-force attempts.

### Q2: What is the difference between NIDS and HIDS?
**Answer:** 
- **NIDS (Network-based IDS)** monitors network traffic across an entire subnet/segment by capturing packets from network interfaces (promiscuous mode).
- **HIDS (Host-based IDS)** monitors local host activities such as file system integrity, system logs, registry changes, and local process calls.

### Q3: How does your application handle Snort alerts?
**Answer:** The backend features a background log listener service that tails Snort's `alert_fast` log format, parses fields using regular expressions into structured data, normalizes timestamps and IP addresses, assigns severity levels based on Snort priorities, and persists alerts into a SQLite database with status set to `New`.

### Q4: How do you handle False Positives in your SOC Dashboard?
**Answer:** Security analysts can click on any alert to inspect the raw Snort log string, packet details, and payload. Analysts can change the alert status to `False Positive` or `Resolved` and append investigation notes. This provides an incident triage workflow that updates security metrics in real time.

---

## License & Compliance
This software is developed strictly for educational, research, and authorized lab testing purposes under Ethical Hacking guidelines.
