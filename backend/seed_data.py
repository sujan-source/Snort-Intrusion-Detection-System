import os
import sys
from datetime import datetime, timedelta
import random

# Add app directory to sys.path
sys.path.insert(0, os.path.dirname(__file__))

from app.core.db import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models.user import User
from app.models.alert import Alert
from app.models.rule import SnortRule
from app.models.audit_log import AuditLog

def seed_database():
    print("[*] Initializing Database Schema...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # 1. Seed Default Users
        if db.query(User).count() == 0:
            print("[+] Seeding Users...")
            admin_user = User(
                username="admin",
                password_hash=get_password_hash("admin123"),
                role="admin"
            )
            analyst_user = User(
                username="analyst",
                password_hash=get_password_hash("analyst123"),
                role="analyst"
            )
            db.add(admin_user)
            db.add(analyst_user)

        # 2. Seed Default Snort Rules
        if db.query(SnortRule).count() == 0:
            print("[+] Seeding Snort Rules...")
            default_rules = [
                SnortRule(
                    sid=1000001, rev=1, msg="NIDS DETECTED: ICMP Ping Sweep / Probe",
                    protocol="icmp", src_net="any", src_port="any", dst_net="any", dst_port="any",
                    action="alert", category="attempted-recon", severity="Medium",
                    raw_rule="alert icmp any any -> any any (msg:\"NIDS DETECTED: ICMP Ping Sweep / Probe\"; icmptype:8; sid:1000001; rev:1; classtype:attempted-recon; priority:3;)",
                    is_active=True
                ),
                SnortRule(
                    sid=1000002, rev=1, msg="NIDS DETECTED: Nmap TCP SYN Port Scan Attempt",
                    protocol="tcp", src_net="any", src_port="any", dst_net="any", dst_port="any",
                    action="alert", category="attempted-recon", severity="High",
                    raw_rule="alert tcp any any -> any any (msg:\"NIDS DETECTED: Nmap TCP SYN Port Scan Attempt\"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)",
                    is_active=True
                ),
                SnortRule(
                    sid=1000003, rev=1, msg="NIDS DETECTED: Stealth NULL Scan Attempt",
                    protocol="tcp", src_net="any", src_port="any", dst_net="any", dst_port="any",
                    action="alert", category="attempted-recon", severity="High",
                    raw_rule="alert tcp any any -> any any (msg:\"NIDS DETECTED: Stealth NULL Scan Attempt\"; flags:0; sid:1000003; rev:1; classtype:attempted-recon; priority:1;)",
                    is_active=True
                ),
                SnortRule(
                    sid=1000005, rev=1, msg="NIDS DETECTED: SSH Brute Force Authentication Attempt",
                    protocol="tcp", src_net="any", src_port="any", dst_net="any", dst_port="22",
                    action="alert", category="suspicious-login", severity="Critical",
                    raw_rule="alert tcp any any -> any 22 (msg:\"NIDS DETECTED: SSH Brute Force Authentication Attempt\"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000005; rev:1; classtype:suspicious-login; priority:1;)",
                    is_active=True
                ),
                SnortRule(
                    sid=1000007, rev=1, msg="NIDS DETECTED: Web Attack - SQL Injection Attempt (' OR 1=1)",
                    protocol="tcp", src_net="any", src_port="any", dst_net="any", dst_port="80",
                    action="alert", category="web-application-attack", severity="Critical",
                    raw_rule="alert tcp any any -> any 80 (msg:\"NIDS DETECTED: Web Attack - SQL Injection Attempt (' OR 1=1)\"; content:\"UNION\"; content:\"SELECT\"; nocase; sid:1000007; rev:1; classtype:web-application-attack; priority:1;)",
                    is_active=True
                ),
                SnortRule(
                    sid=1000009, rev=1, msg="NIDS DETECTED: DNS Anomaly - Large Payload / Amplification Query",
                    protocol="udp", src_net="any", src_port="any", dst_net="any", dst_port="53",
                    action="alert", category="bad-unknown", severity="High",
                    raw_rule="alert udp any any -> any 53 (msg:\"NIDS DETECTED: DNS Anomaly - Large Payload / Amplification Query\"; dsize:>512; sid:1000009; rev:1; classtype:bad-unknown; priority:2;)",
                    is_active=True
                )
            ]
            db.add_all(default_rules)

        # 3. Seed Realistic Initial Alerts
        if db.query(Alert).count() == 0:
            print("[+] Seeding Initial Security Alerts...")
            now = datetime.utcnow()
            
            sample_alerts = [
                {
                    "sid": 1000005, "rev": 1, "offset_min": 10,
                    "src": "185.220.101.5", "dst": "192.168.1.10", "sport": 54210, "dport": 22,
                    "proto": "TCP", "type": "Brute-Force Attack", "sev": "Critical",
                    "msg": "NIDS DETECTED: SSH Brute Force Authentication Attempt", "status": "New"
                },
                {
                    "sid": 1000007, "rev": 1, "offset_min": 25,
                    "src": "45.33.32.156", "dst": "192.168.1.100", "sport": 49152, "dport": 80,
                    "proto": "TCP", "type": "Web Application Attack", "sev": "Critical",
                    "msg": "NIDS DETECTED: Web Attack - SQL Injection Attempt (' OR 1=1)", "status": "Investigating"
                },
                {
                    "sid": 1000002, "rev": 1, "offset_min": 45,
                    "src": "192.168.1.105", "dst": "192.168.1.1", "sport": 60124, "dport": 80,
                    "proto": "TCP", "type": "Port Scanning", "sev": "High",
                    "msg": "NIDS DETECTED: Nmap TCP SYN Port Scan Attempt", "status": "New"
                },
                {
                    "sid": 1000009, "rev": 1, "offset_min": 120,
                    "src": "198.51.100.44", "dst": "192.168.1.1", "sport": 5353, "dport": 53,
                    "proto": "UDP", "type": "DNS Anomaly", "sev": "High",
                    "msg": "NIDS DETECTED: DNS Anomaly - Large Payload / Amplification Query", "status": "Resolved"
                },
                {
                    "sid": 1000001, "rev": 1, "offset_min": 180,
                    "src": "10.0.0.88", "dst": "10.0.0.1", "sport": None, "dport": None,
                    "proto": "ICMP", "type": "ICMP Scanning / Recon", "sev": "Medium",
                    "msg": "NIDS DETECTED: ICMP Ping Sweep / Probe", "status": "False Positive"
                },
                {
                    "sid": 1000003, "rev": 1, "offset_min": 240,
                    "src": "172.16.0.99", "dst": "192.168.1.100", "sport": 51200, "dport": 443,
                    "proto": "TCP", "type": "Port Scanning", "sev": "High",
                    "msg": "NIDS DETECTED: Stealth NULL Scan Attempt", "status": "New"
                }
            ]

            for item in sample_alerts:
                alert_time = now - timedelta(minutes=item["offset_min"])
                ts_str = alert_time.strftime("%m/%d-%H:%M:%S.%f")[:21]
                raw = f"{ts_str} [**] [1:{item['sid']}:{item['rev']}] {item['msg']} [**] [Priority: 2] {{{item['proto']}}} {item['src']} -> {item['dst']}"
                
                alert = Alert(
                    sid=item["sid"],
                    rev=item["rev"],
                    timestamp=alert_time,
                    source_ip=item["src"],
                    destination_ip=item["dst"],
                    source_port=item["sport"],
                    destination_port=item["dport"],
                    protocol=item["proto"],
                    attack_type=item["type"],
                    severity=item["sev"],
                    msg=item["msg"],
                    status=item["status"],
                    raw_alert=raw,
                    notes="Initial seed event for SOC dashboard baseline."
                )
                db.add(alert)

        # 4. Seed Audit Log
        if db.query(AuditLog).count() == 0:
            print("[+] Seeding Audit Logs...")
            db.add(AuditLog(
                username="system",
                action="SYSTEM_INIT",
                details="Snort NIDS engine initialized and database seeded successfully.",
                ip_address="127.0.0.1"
            ))

        db.commit()
        print("[+] Database Seeded Successfully!")
    except Exception as e:
        db.rollback()
        print(f"[!] Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
