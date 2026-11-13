import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
import os

def set_cell_background(cell, fill_hex):
    tcPr = cell._element.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._element.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def add_heading_styled(doc, text, level):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    
    run = p.add_run(text)
    run.font.name = 'Segoe UI'
    run.bold = True
    
    if level == 1:
        run.font.size = Pt(18)
        run.font.color.rgb = RGBColor(2, 132, 199) # Dark Cyan Blue
        p.paragraph_format.space_before = Pt(22)
    elif level == 2:
        run.font.size = Pt(14)
        run.font.color.rgb = RGBColor(15, 23, 42) # Slate Dark
    elif level == 3:
        run.font.size = Pt(12)
        run.font.color.rgb = RGBColor(51, 65, 85) # Slate Medium
    return p

def create_callout_box(doc, text, title="NOTE"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F0F9FF") # Light blue fill
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    r_title = p.add_run(f"[{title}] ")
    r_title.bold = True
    r_title.font.name = 'Segoe UI'
    r_title.font.size = Pt(10)
    r_title.font.color.rgb = RGBColor(2, 132, 199)
    
    r_text = p.add_run(text)
    r_text.font.name = 'Segoe UI'
    r_text.font.size = Pt(10)
    r_text.font.color.rgb = RGBColor(30, 41, 59)
    doc.add_paragraph() # Spacer

def generate_report():
    doc = docx.Document()

    # Set Margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Base Normal Style
    style_normal = doc.styles['Normal']
    font = style_normal.font
    font.name = 'Segoe UI'
    font.size = Pt(11)
    font.color.rgb = RGBColor(30, 41, 59)

    # ==========================================
    # COVER / TITLE SECTION
    # ==========================================
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(36)
    title_p.paragraph_format.space_after = Pt(12)
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title_p.add_run("INTRUSION DETECTION USING SNORT")
    r.font.name = 'Segoe UI'
    r.font.size = Pt(26)
    r.bold = True
    r.font.color.rgb = RGBColor(2, 132, 199)

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(36)
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_sub = sub_p.add_run("A Complete Network Intrusion Detection System & Security Operations Center (SOC) Project Report")
    r_sub.font.name = 'Segoe UI'
    r_sub.font.size = Pt(13)
    r_sub.italic = True
    r_sub.font.color.rgb = RGBColor(100, 116, 139)

    # Meta Table
    meta_tbl = doc.add_table(rows=4, cols=2)
    meta_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Course Name:", "Ethical Hacking & Cybersecurity"),
        ("Project Title:", "Intrusion Detection Using Snort"),
        ("Technology Stack:", "Snort 2.9, Python FastAPI, SQLite, HTML5/CSS3/JS, Chart.js"),
        ("Academic Year:", "2026")
    ]
    for idx, (label, val) in enumerate(meta_data):
        c0 = meta_tbl.cell(idx, 0)
        c1 = meta_tbl.cell(idx, 1)
        c0.text = label
        c1.text = val
        c0.paragraphs[0].runs[0].font.bold = True
        c0.paragraphs[0].runs[0].font.color.rgb = RGBColor(15, 23, 42)
        c1.paragraphs[0].runs[0].font.color.rgb = RGBColor(51, 65, 85)
        set_cell_background(c0, "F8FAFC")
        set_cell_background(c1, "F8FAFC")
        set_cell_margins(c0, top=100, bottom=100, left=150, right=150)
        set_cell_margins(c1, top=100, bottom=100, left=150, right=150)

    doc.add_page_break()

    # ==========================================
    # CHAPTER 1: INTRODUCTION & PROJECT OBJECTIVES
    # ==========================================
    add_heading_styled(doc, "Chapter 1: Introduction & Project Objectives", level=1)
    
    add_heading_styled(doc, "1.1 Introduction", level=2)
    p = doc.add_paragraph(
        "Modern computer networks face continuous threats from sophisticated cyber attacks, ranging from unauthorized reconnaissance "
        "scans to destructive malware payloads and brute-force authentication floods. To defend against these malicious activities, "
        "organizations deploy Network-based Intrusion Detection Systems (NIDS). An NIDS acts as an automated security monitor that intercepts "
        "and inspects network traffic packets in real time to detect unauthorized access, policy violations, and attack signatures."
    )
    p.paragraph_format.space_after = Pt(8)

    p2 = doc.add_paragraph(
        "Snort is an industry-standard, open-source packet inspection engine capable of performing real-time traffic analysis, packet logging, "
        "and signature-based detection. However, raw Snort alert logs (produced in text files such as alert_fast) present significant operational "
        "challenges for Security Operations Center (SOC) analysts who require immediate visualization, filtering, incident lifecycle tracking, "
        "and executive reporting."
    )
    p2.paragraph_format.space_after = Pt(8)

    p3 = doc.add_paragraph(
        "This project presents a production-grade, full-stack NIDS platform titled 'Intrusion Detection Using Snort'. "
        "The system integrates Snort's rule-based detection engine with a high-performance Python FastAPI backend, a SQLite database, "
        "an interactive dark-themed SOC web interface built with HTML5, CSS3, JavaScript, and Chart.js, and an automated ReportLab PDF "
        "export module."
    )
    p3.paragraph_format.space_after = Pt(12)

    add_heading_styled(doc, "1.2 Project Objectives", level=2)
    objectives = [
        ("Network Packet Inspection & Rule Matching: ", "Integrate Snort NIDS signatures (rules/local.rules) to analyze network packets and detect authorized test attack scenarios such as ICMP sweeps, Nmap SYN scans, SSH brute force, SQL injection, and DNS amplification queries."),
        ("Log Parsing & Normalization: ", "Develop an automated background parser (snort_parser.py) that reads raw Snort alert_fast output, normalizes timestamps, IPs, ports, and protocols, and assigns severity levels based on Snort priorities."),
        ("Database Storage & Auditing: ", "Store all normalized security alerts, user accounts, Snort rules, and administrative actions inside a structured SQLite database using SQLAlchemy ORM."),
        ("Modern SOC Web Dashboard: ", "Design an interactive, dark-themed Security Operations Center UI featuring real-time KPI tiles (Total Monitored Packets, Total Intrusions, Critical/High/Med/Low breakdowns), dynamic Chart.js visualizations, and a live alert stream."),
        ("Incident Lifecycle Triage: ", "Provide a full incident management workflow allowing security analysts to investigate packet headers, change alert statuses (New, Investigating, False Positive, Resolved), and log analyst notes."),
        ("Isolated Lab Attack Simulator: ", "Engineer an integrated attack generator allowing one-click execution of synthetic attack vectors for viva defense and testing without requiring external hacking tools."),
        ("Executive Security Reporting: ", "Generate security summary reports with automated defensive mitigation recommendations (iptables rules, Snort drop signatures, fail2ban setup) and downloadable PDF export."),
        ("Role-Based Access Control (RBAC): ", "Secure the platform with OAuth2 JWT authentication, bcrypt password hashing, and role-based permissions separating Administrator and Analyst capabilities.")
    ]

    for title, desc in objectives:
        p_obj = doc.add_paragraph(style='List Bullet')
        p_obj.paragraph_format.space_after = Pt(4)
        r_t = p_obj.add_run(title)
        r_t.bold = True
        r_t.font.color.rgb = RGBColor(2, 132, 199)
        r_d = p_obj.add_run(desc)

    doc.add_page_break()

    # ==========================================
    # CHAPTER 2: PROJECT GUIDELINES & LAB SETUP
    # ==========================================
    add_heading_styled(doc, "Chapter 2: Project Guidelines & Lab Setup", level=1)

    add_heading_styled(doc, "2.1 Project Guidelines", level=2)
    p_guide = doc.add_paragraph(
        "To ensure compliance with academic ethical hacking guidelines, legal regulations, and safety standards, "
        "this project operates strictly under the following mandatory principles:"
    )
    p_guide.paragraph_format.space_after = Pt(8)

    guidelines_list = [
        ("Authorized Lab Traffic Only: ", "All attack vectors, port scans, and payload injections must be restricted to isolated loopback environments (127.0.0.1) or dedicated lab subnets (192.168.x.x / 10.0.x.x)."),
        ("Non-Destructive Simulation: ", "Attack vectors generated by the built-in simulator are strictly non-destructive signatures designed to validate Snort rule matching without harming system stability."),
        ("Production Code Standards: ", "The backend code follows modern PEP-8, modular architecture, explicit Pydantic schema validation, and secure ORM parameter binding to eliminate SQL injection vulnerabilities.")
    ]

    for title, desc in guidelines_list:
        p_g = doc.add_paragraph(style='List Bullet')
        p_g.paragraph_format.space_after = Pt(4)
        r_t = p_g.add_run(title)
        r_t.bold = True
        r_d = p_g.add_run(desc)

    add_heading_styled(doc, "2.2 Lab Setup", level=2)
    p_lab = doc.add_paragraph(
        "The project is engineered for cross-platform deployment across Linux (Kali Linux, Ubuntu, Debian) and Windows (10/11) operating systems."
    )
    p_lab.paragraph_format.space_after = Pt(8)

    add_heading_styled(doc, "System & Software Requirements", level=3)
    
    req_table = doc.add_table(rows=5, cols=2)
    req_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    req_data = [
        ("Operating System", "Linux (Kali Linux / Ubuntu 22.04 LTS) or Windows 10/11"),
        ("NIDS Engine", "Snort 2.9.x / 3.x Daemon"),
        ("Runtime Environment", "Python 3.9+ (Python 3.13 tested)"),
        ("Backend Packages", "FastAPI, Uvicorn, SQLAlchemy, Pydantic, PyJWT, Bcrypt, ReportLab, python-docx"),
        ("Frontend Technologies", "HTML5, CSS3 (Tactical Dark SOC Theme), JavaScript ES6+, Chart.js, Bootstrap 5")
    ]
    for idx, (comp, detail) in enumerate(req_data):
        c0 = req_table.cell(idx, 0)
        c1 = req_table.cell(idx, 1)
        c0.text = comp
        c1.text = detail
        c0.paragraphs[0].runs[0].font.bold = True
        set_cell_background(c0, "F1F5F9")
        set_cell_background(c1, "FFFFFF")
        set_cell_margins(c0, top=100, bottom=100, left=150, right=150)
        set_cell_margins(c1, top=100, bottom=100, left=150, right=150)

    doc.add_paragraph()

    add_heading_styled(doc, "Snort Installation & Linux Daemon Execution", level=3)
    create_callout_box(
        doc,
        "1. Install Snort on Kali/Ubuntu:\n   sudo apt-get update && sudo apt-get install snort -y\n\n"
        "2. Copy rules file to Snort config:\n   cp backend/rules/local.rules /etc/snort/rules/local.rules\n\n"
        "3. Run Snort in Fast Alert Mode:\n   sudo snort -A fast -c /etc/snort/snort.conf -i eth0 -l /var/log/snort/",
        title="LINUX LAB SETUP STEPS"
    )

    doc.add_page_break()

    # ==========================================
    # CHAPTER 3: PROBLEM STATEMENT & TECHNICAL SPECIFICATION
    # ==========================================
    add_heading_styled(doc, "Chapter 3: Problem Statement, Background & Implementation", level=1)

    add_heading_styled(doc, "3.1 Problem Statement", level=2)
    doc.add_paragraph(
        "Command-line intrusion detection systems like Snort excel at inspecting network packets, but output raw text log strings "
        "that are difficult for Security Operations Center (SOC) analysts to triaging in real time. Organizations face critical "
        "delays in detecting stealth scans, brute force attempts, and web attacks due to the lack of consolidated visual monitoring, "
        "automated rule parsing, incident lifecycle tracking, and actionable defensive recommendations."
    )

    add_heading_styled(doc, "3.2 Background", level=2)
    doc.add_paragraph(
        "Network Intrusion Detection Systems operate primarily through two methodologies:\n"
        "1. Signature-Based Detection: Comparing packet headers and content against known attack signatures (used by Snort).\n"
        "2. Anomaly-Based Detection: Establishing baseline normal behavior and flagging statistical deviations.\n\n"
        "This project leverages signature-based detection for high precision and zero false positives on known threat patterns, "
        "augmenting it with a modern web dashboard and triage workflow."
    )

    add_heading_styled(doc, "3.3 Tools Required", level=2)
    doc.add_paragraph(
        "• Snort Engine: Inspects raw ethernet packets using local.rules.\n"
        "• FastAPI & Uvicorn: Asynchronous web server hosting RESTful API endpoints.\n"
        "• SQLAlchemy & SQLite: Relational persistence layer storing alerts, rules, users, and audit logs.\n"
        "• Chart.js: Client-side visualization library rendering trend lines and doughnut charts.\n"
        "• ReportLab & python-docx: Automated PDF and Word document generators."
    )

    add_heading_styled(doc, "3.4 Implementation Tasks", level=2)
    
    tasks_data = [
        ("Task 1: Database Architecture", "Implemented SQLAlchemy models for User, Alert, SnortRule, and AuditLog with indexed fields for fast querying."),
        ("Task 2: Snort Log Listener", "Developed snort_parser.py with regex to parse alert_fast log lines (timestamp, SID, rev, IPs, ports, protocol, severity, msg)."),
        ("Task 3: RESTful API Layer", "Built routers under /api for auth (JWT/bcrypt), alerts (filtering/pagination/status update), stats, rules management, simulation, and reports."),
        ("Task 4: SOC Web Frontend", "Created dark-themed HTML/CSS/JS templates (index.html, alerts.html, rules.html, simulator.html, reports.html, login.html)."),
        ("Task 5: Attack Simulator", "Engineered simulator.py to generate non-destructive synthetic attack alerts for lab viva testing."),
        ("Task 6: Mitigation Engine", "Built automated defensive action mapping (iptables rules, Snort drop signatures, fail2ban setup) exported via PDF/Word.")
    ]

    for title, desc in tasks_data:
        p_t = doc.add_paragraph(style='List Bullet')
        p_t.paragraph_format.space_after = Pt(4)
        r1 = p_t.add_run(f"{title}: ")
        r1.bold = True
        r1.font.color.rgb = RGBColor(2, 132, 199)
        p_t.add_run(desc)

    add_heading_styled(doc, "3.5 Mapping to Syllabus Units", level=2)
    
    syl_table = doc.add_table(rows=5, cols=2)
    syl_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    syl_data = [
        ("Unit 1: Security Fundamentals & Recon", "Port scanning (Nmap SYN, NULL, Xmas scan), ICMP host sweeps, stealth recon techniques."),
        ("Unit 2: Network Security & Firewalls", "Packet filtering, Snort NIDS architecture, signature-based rules, traffic inspection."),
        ("Unit 3: Web Application Security", "SQL injection detection (' OR 1=1), directory traversal path escalation."),
        ("Unit 4: Incident Response & SOC Operations", "Incident triage lifecycle (New -> Investigating -> Resolved), defense-in-depth, security reporting.")
    ]
    for idx, (unit, desc) in enumerate(syl_data):
        c0 = syl_table.cell(idx, 0)
        c1 = syl_table.cell(idx, 1)
        c0.text = unit
        c1.text = desc
        c0.paragraphs[0].runs[0].font.bold = True
        set_cell_background(c0, "F1F5F9")
        set_cell_background(c1, "FFFFFF")
        set_cell_margins(c0, top=100, bottom=100, left=150, right=150)
        set_cell_margins(c1, top=100, bottom=100, left=150, right=150)

    doc.add_page_break()

    # ==========================================
    # CHAPTER 4: SCREENSHOT GUIDELINES & REPOSITORY STRUCTURE
    # ==========================================
    add_heading_styled(doc, "Chapter 4: Screenshot Guidelines & Repository Structure", level=1)

    add_heading_styled(doc, "4.1 Screenshot Guidelines", level=2)
    doc.add_paragraph(
        "Below are the recommended screenshot capture guidelines for inclusion in final academic project submissions and viva presentations:"
    )

    scr_list = [
        ("Figure 4.1: SOC Dashboard Overview (http://127.0.0.1:8080/)", "Capture the main SOC dashboard showing KPI tiles (Packets Inspected, Intrusions Detected, Critical Threats), velocity line chart, protocol doughnut chart, and live alert stream."),
        ("Figure 4.2: Security Alerts Feed & Triage (http://127.0.0.1:8080/alerts-page)", "Capture the alerts investigation table, showing search filters, dark theme contrast, status badges, and the Incident Triage Modal with analyst notes."),
        ("Figure 4.3: Snort Rules Catalog (http://127.0.0.1:8080/rules-page)", "Capture the Snort rules catalog detailing SID signatures (local.rules), protocols, severity mappings, and the custom rule creation modal."),
        ("Figure 4.4: Isolated Lab Attack Simulator (http://127.0.0.1:8080/simulator-page)", "Capture the lab attack simulator page highlighting vector cards (Nmap SYN, SSH Brute Force, SQL Injection) and live terminal execution logs."),
        ("Figure 4.5: Executive Security Report & Defense Guidelines (http://127.0.0.1:8080/reports-page)", "Capture the executive threat summary, automated iptables defensive guidelines, and the Download PDF Report trigger."),
        ("Figure 4.6: Admin Authentication Portal (http://127.0.0.1:8080/login)", "Capture the JWT-secured login screen demonstrating role-based authentication.")
    ]

    for fig, desc in scr_list:
        p_s = doc.add_paragraph(style='List Bullet')
        p_s.paragraph_format.space_after = Pt(4)
        r_f = p_s.add_run(f"{fig}: ")
        r_f.bold = True
        r_f.font.color.rgb = RGBColor(2, 132, 199)
        p_s.add_run(desc)

    add_heading_styled(doc, "4.2 GitHub Repository Structure", level=2)
    
    code_block = doc.add_paragraph()
    code_block.paragraph_format.space_before = Pt(6)
    code_block.paragraph_format.space_after = Pt(12)
    r_cb = code_block.add_run(
        "Ethical Hacing Project 2/\n"
        "├── backend/\n"
        "│   ├── app/\n"
        "│   │   ├── api/             # API routers (auth, alerts, stats, rules, simulation, reports, audit)\n"
        "│   │   ├── core/            # App config, JWT/bcrypt security, DB session\n"
        "│   │   ├── models/          # SQLAlchemy DB models (User, Alert, SnortRule, AuditLog)\n"
        "│   │   ├── schemas/         # Pydantic validation schemas\n"
        "│   │   ├── services/        # Snort log parser, attack simulator, report generator\n"
        "│   │   └── main.py          # FastAPI application entry point\n"
        "│   ├── rules/\n"
        "│   │   └── local.rules      # Snort local signature definitions\n"
        "│   ├── requirements.txt     # Python backend dependencies\n"
        "│   └── seed_data.py         # Database initialization and sample data seeder\n"
        "├── frontend/\n"
        "│   ├── static/\n"
        "│   │   ├── css/\n"
        "│   │   │   └── soc_style.css # Modern dark SOC glassmorphism stylesheet\n"
        "│   │   └── js/              # App logic, Chart.js visualizations, rules & simulator handlers\n"
        "│   └── templates/           # HTML templates (index, alerts, rules, simulator, reports, login)\n"
        "├── run.py                   # One-click unified application launcher\n"
        "└── README.md                # Project documentation and viva guide"
    )
    r_cb.font.name = 'Consolas'
    r_cb.font.size = Pt(9.5)
    r_cb.font.color.rgb = RGBColor(2, 132, 199)

    out_path = os.path.join(os.path.dirname(__file__), "Intrusion_Detection_Using_Snort_Project_Report.docx")
    doc.save(out_path)
    print(f"[+] Document saved successfully to: {out_path}")

if __name__ == "__main__":
    generate_report()
