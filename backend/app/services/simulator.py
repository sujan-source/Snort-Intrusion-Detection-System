import random
import os
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.core.config import settings

ATTACK_PRESETS = {
    "nmap_syn": {
        "sid": 1000002,
        "rev": 1,
        "msg": "NIDS DETECTED: Nmap TCP SYN Port Scan Attempt",
        "protocol": "TCP",
        "attack_type": "Port Scanning",
        "severity": "High",
        "dst_port": 80,
        "default_src": "192.168.1.105",
        "default_dst": "192.168.1.1",
        "raw_template": "{ts} [**] [1:1000002:1] NIDS DETECTED: Nmap TCP SYN Port Scan Attempt [**] [Classification: attempted-recon] [Priority: 2] {{TCP}} {src_ip}:{src_port} -> {dst_ip}:80"
    },
    "icmp_sweep": {
        "sid": 1000001,
        "rev": 1,
        "msg": "NIDS DETECTED: ICMP Ping Sweep / Probe",
        "protocol": "ICMP",
        "attack_type": "ICMP Scanning / Recon",
        "severity": "Medium",
        "dst_port": None,
        "src_port": None,
        "default_src": "10.0.0.88",
        "default_dst": "10.0.0.1",
        "raw_template": "{ts} [**] [1:1000001:1] NIDS DETECTED: ICMP Ping Sweep / Probe [**] [Classification: attempted-recon] [Priority: 3] {{ICMP}} {src_ip} -> {dst_ip}"
    },
    "ssh_brute": {
        "sid": 1000005,
        "rev": 1,
        "msg": "NIDS DETECTED: SSH Brute Force Authentication Attempt",
        "protocol": "TCP",
        "attack_type": "Brute-Force Attack",
        "severity": "Critical",
        "dst_port": 22,
        "default_src": "185.220.101.5",
        "default_dst": "192.168.1.10",
        "raw_template": "{ts} [**] [1:1000005:1] NIDS DETECTED: SSH Brute Force Authentication Attempt [**] [Classification: suspicious-login] [Priority: 1] {{TCP}} {src_ip}:{src_port} -> {dst_ip}:22"
    },
    "sqli": {
        "sid": 1000007,
        "rev": 1,
        "msg": "NIDS DETECTED: Web Attack - SQL Injection Attempt (' OR 1=1)",
        "protocol": "TCP",
        "attack_type": "Web Application Attack",
        "severity": "Critical",
        "dst_port": 80,
        "default_src": "45.33.32.156",
        "default_dst": "192.168.1.100",
        "raw_template": "{ts} [**] [1:1000007:1] NIDS DETECTED: Web Attack - SQL Injection Attempt (' OR 1=1) [**] [Classification: web-application-attack] [Priority: 1] {{TCP}} {src_ip}:{src_port} -> {dst_ip}:80"
    },
    "dns_anomaly": {
        "sid": 1000009,
        "rev": 1,
        "msg": "NIDS DETECTED: DNS Anomaly - Large Payload / Amplification Query",
        "protocol": "UDP",
        "attack_type": "DNS Anomaly",
        "severity": "High",
        "dst_port": 53,
        "default_src": "198.51.100.44",
        "default_dst": "192.168.1.1",
        "raw_template": "{ts} [**] [1:1000009:1] NIDS DETECTED: DNS Anomaly - Large Payload / Amplification Query [**] [Classification: bad-unknown] [Priority: 2] {{UDP}} {src_ip}:{src_port} -> {dst_ip}:53"
    },
    "null_scan": {
        "sid": 1000003,
        "rev": 1,
        "msg": "NIDS DETECTED: Stealth NULL Scan Attempt",
        "protocol": "TCP",
        "attack_type": "Port Scanning",
        "severity": "High",
        "dst_port": 443,
        "default_src": "172.16.0.99",
        "default_dst": "192.168.1.100",
        "raw_template": "{ts} [**] [1:1000003:1] NIDS DETECTED: Stealth NULL Scan Attempt [**] [Classification: attempted-recon] [Priority: 1] {{TCP}} {src_ip}:{src_port} -> {dst_ip}:443"
    }
}

def generate_simulated_alert(db: Session, attack_key: str, target_ip: str = None, source_ip: str = None) -> Alert:
    preset = ATTACK_PRESETS.get(attack_key, ATTACK_PRESETS["nmap_syn"])
    
    src_ip = source_ip or preset["default_src"]
    dst_ip = target_ip or preset["default_dst"]
    src_port = random.randint(1024, 65535) if preset["protocol"] != "ICMP" else None
    dst_port = preset["dst_port"]
    
    now = datetime.utcnow()
    ts_formatted = now.strftime("%m/%d-%H:%M:%S.%f")[:21]
    
    raw_str = preset["raw_template"].format(
        ts=ts_formatted,
        src_ip=src_ip,
        src_port=src_port or 0,
        dst_ip=dst_ip
    )
    
    # Save to Snort log file for log tailing consistency
    try:
        with open(settings.SNORT_ALERT_FILE, "a") as f:
            f.write(raw_str + "\n")
    except Exception:
        pass
        
    alert = Alert(
        sid=preset["sid"],
        rev=preset["rev"],
        timestamp=now,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=preset["protocol"],
        attack_type=preset["attack_type"],
        severity=preset["severity"],
        msg=preset["msg"],
        status="New",
        raw_alert=raw_str,
        notes="Generated via Lab Attack Simulator for viva demonstration."
    )
    
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
