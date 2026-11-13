from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.alert import Alert
from datetime import datetime, timedelta
from typing import Dict, Any, List

RECOMMENDED_DEFENSES = {
    "Port Scanning": [
        "Deploy iptables rate-limiting rules (e.g., `iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set`).",
        "Enable Snort inline drop rules: `drop tcp any any -> $HOME_NET any (flags:S; threshold:type threshold, track by_src, count 10, seconds 5;)`.",
        "Disable unneeded listening ports and services on host systems."
    ],
    "ICMP Scanning / Recon": [
        "Block incoming ICMP Echo Requests (Ping) at the perimeter firewall (`iptables -A INPUT -p icmp --icmp-type echo-request -j DROP`).",
        "Disable response to broadcast pings in kernel configuration (`net.ipv4.icmp_echo_ignore_broadcasts = 1`)."
    ],
    "Brute-Force Attack": [
        "Implement Fail2Ban or SSHGuard to automatically ban IPs exceeding authentication failure limits.",
        "Enforce Multi-Factor Authentication (MFA) and SSH key-based authentication while disabling password logins.",
        "Change default admin and SSH ports (e.g., move SSH from port 22 to high non-standard port)."
    ],
    "Web Application Attack": [
        "Deploy a Web Application Firewall (WAF) such as ModSecurity or Cloudflare.",
        "Use parameterized queries / prepared statements in database interactions to completely mitigate SQL Injection.",
        "Sanitize and validate all incoming HTTP input parameters."
    ],
    "DNS Anomaly": [
        "Configure DNS response rate limiting (RRL) to prevent DNS amplification attacks.",
        "Restrict open DNS recursors to internal network subnets only.",
        "Enable DNSSEC validation on authoritative domain servers."
    ],
    "Unauthorized Access": [
        "Disable insecure legacy protocols (Telnet, FTP, HTTP) and force encrypted equivalents (SSH, SFTP, HTTPS).",
        "Implement strict network segmentation using VLANs and Access Control Lists (ACLs)."
    ]
}

def generate_security_report_data(db: Session, days: int = 7) -> Dict[str, Any]:
    since_date = datetime.utcnow() - timedelta(days=days)
    
    total_alerts = db.query(Alert).filter(Alert.timestamp >= since_date).count()
    critical_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.severity == "Critical").count()
    high_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.severity == "High").count()
    med_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.severity == "Medium").count()
    low_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.severity == "Low").count()
    
    # Common Attack Types
    attack_types = (
        db.query(Alert.attack_type, func.count(Alert.id).label("count"))
        .filter(Alert.timestamp >= since_date)
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    
    # Top Source IPs
    top_sources = (
        db.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .filter(Alert.timestamp >= since_date)
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    
    # Status Breakdown
    resolved_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.status == "Resolved").count()
    investigating_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.status == "Investigating").count()
    false_pos_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.status == "False Positive").count()
    new_cnt = db.query(Alert).filter(Alert.timestamp >= since_date, Alert.status == "New").count()
    
    # Compile Defensive Recommendations based on detected attacks
    defensive_actions: List[Dict[str, Any]] = []
    seen_types = set()
    for atype, cnt in attack_types:
        seen_types.add(atype)
        recs = RECOMMENDED_DEFENSES.get(atype, [
            "Monitor network traffic logs continuously for anomalous connections.",
            "Maintain updated signature databases and apply security patches."
        ])
        defensive_actions.append({
            "attack_type": atype,
            "incident_count": cnt,
            "recommendations": recs
        })
        
    return {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "timeframe_days": days,
        "metrics": {
            "total_alerts": total_alerts,
            "critical": critical_cnt,
            "high": high_cnt,
            "medium": med_cnt,
            "low": low_cnt,
            "new": new_cnt,
            "investigating": investigating_cnt,
            "resolved": resolved_cnt,
            "false_positive": false_pos_cnt
        },
        "attack_types": [{"type": atype, "count": cnt} for atype, cnt in attack_types],
        "top_sources": [{"ip": ip, "count": cnt} for ip, cnt in top_sources],
        "defensive_actions": defensive_actions
    }
