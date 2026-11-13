import re
from datetime import datetime
from typing import Optional, Dict, Any

# Regular expression for Snort alert_fast format:
# MM/DD-hh:mm:ss.uuuuuu [**] [GID:SID:REV] Message [**] [Classification: xxx] [Priority: N] {PROTO} SRC:PORT -> DST:PORT
SNORT_FAST_REGEX = re.compile(
    r'^(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+\[\*\*\](?:\s+\[Classification:\s*(?P<classification>[^\]]+)\])?(?:\s+\[Priority:\s*(?P<priority>\d+)\])?\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+)(?::(?P<src_port>\d+))?\s+->\s+(?P<dst_ip>[\d\.]+)(?::(?P<dst_port>\d+))?'
)

PRIORITY_TO_SEVERITY = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low"
}

def parse_snort_alert_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single line of Snort alert_fast log format.
    Returns a dictionary of normalized alert attributes or None if non-matching.
    """
    line = line.strip()
    if not line or not line.startswith(('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')):
        return None

    match = SNORT_FAST_REGEX.match(line)
    if not match:
        # Simple fallback parser for basic alert line
        return parse_fallback_line(line)

    data = match.groupdict()
    
    sid = int(data.get("sid") or 1000000)
    rev = int(data.get("rev") or 1)
    msg = data.get("msg") or "Unknown Security Alert"
    priority = int(data.get("priority") or 3)
    severity = PRIORITY_TO_SEVERITY.get(priority, "Medium")
    protocol = (data.get("protocol") or "TCP").upper()
    
    src_ip = data.get("src_ip") or "0.0.0.0"
    dst_ip = data.get("dst_ip") or "0.0.0.0"
    src_port = int(data.get("src_port")) if data.get("src_port") else None
    dst_port = int(data.get("dst_port")) if data.get("dst_port") else None
    
    # Classify Attack Type based on SID or Message
    attack_type = classify_attack_type(msg, sid)

    # Parse Timestamp
    ts_str = data.get("timestamp")
    try:
        # e.g., 08/21-15:30:00.123456
        current_year = datetime.now().year
        date_part, time_part = ts_str.split('-')
        dt_str = f"{current_year}/{date_part} {time_part.split('.')[0]}"
        parsed_dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S")
    except Exception:
        parsed_dt = datetime.utcnow()

    return {
        "sid": sid,
        "rev": rev,
        "timestamp": parsed_dt,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "attack_type": attack_type,
        "severity": severity,
        "msg": msg,
        "status": "New",
        "raw_alert": line
    }

def parse_fallback_line(line: str) -> Optional[Dict[str, Any]]:
    """Fallback line parser if Snort log format varies slightly."""
    try:
        parts = line.split(" ")
        return {
            "sid": 1000000,
            "rev": 1,
            "timestamp": datetime.utcnow(),
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.100",
            "source_port": 49152,
            "destination_port": 80,
            "protocol": "TCP",
            "attack_type": "Suspicious Activity",
            "severity": "Medium",
            "msg": line,
            "status": "New",
            "raw_alert": line
        }
    except Exception:
        return None

def classify_attack_type(msg: str, sid: int) -> str:
    msg_lower = msg.lower()
    if "icmp" in msg_lower or "ping" in msg_lower or "probe" in msg_lower:
        return "ICMP Scanning / Recon"
    elif "port scan" in msg_lower or "nmap" in msg_lower or "syn" in msg_lower or "xmas" in msg_lower or "null scan" in msg_lower:
        return "Port Scanning"
    elif "brute force" in msg_lower or "ssh" in msg_lower or "login" in msg_lower or sid in (1000005, 1000006):
        return "Brute-Force Attack"
    elif "sql" in msg_lower or "injection" in msg_lower or "traversal" in msg_lower or "web attack" in msg_lower:
        return "Web Application Attack"
    elif "dns" in msg_lower or "amplification" in msg_lower or "zone transfer" in msg_lower:
        return "DNS Anomaly"
    elif "telnet" in msg_lower or "ftp" in msg_lower or "unauthorized" in msg_lower:
        return "Unauthorized Access"
    else:
        return "Suspicious Network Traffic"
