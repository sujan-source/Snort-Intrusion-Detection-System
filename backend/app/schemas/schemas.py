from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# --- User & Auth Schemas ---
class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class UserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Alert Schemas ---
class AlertStatusUpdate(BaseModel):
    status: str # "New", "Investigating", "False Positive", "Resolved"
    notes: Optional[str] = None

class AlertOut(BaseModel):
    id: int
    sid: int
    rev: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    attack_type: str
    severity: str
    msg: str
    status: str
    notes: Optional[str] = None
    raw_alert: Optional[str] = None
    payload_hex: Optional[str] = None

    class Config:
        from_attributes = True

class AlertPaginated(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    alerts: List[AlertOut]

# --- Rule Schemas ---
class RuleCreate(BaseModel):
    sid: int
    rev: Optional[int] = 1
    msg: str
    protocol: str
    src_net: Optional[str] = "any"
    src_port: Optional[str] = "any"
    dst_net: Optional[str] = "any"
    dst_port: Optional[str] = "any"
    action: Optional[str] = "alert"
    category: Optional[str] = "attempted-recon"
    severity: Optional[str] = "Medium"
    raw_rule: str
    is_active: Optional[bool] = True

class RuleOut(BaseModel):
    id: int
    sid: int
    rev: int
    msg: str
    protocol: str
    src_net: str
    src_port: str
    dst_net: str
    dst_port: str
    action: str
    category: str
    severity: str
    raw_rule: str
    is_active: bool

    class Config:
        from_attributes = True

# --- Simulation Schema ---
class SimulationTrigger(BaseModel):
    attack_type: str # "icmp_sweep", "nmap_syn", "ssh_brute", "sqli", "dns_anomaly", "null_scan"
    target_ip: Optional[str] = "192.168.1.100"
    source_ip: Optional[str] = "10.0.0.45"

# --- Audit Log Schema ---
class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime
    username: str
    action: str
    details: Optional[str] = None
    ip_address: str

    class Config:
        from_attributes = True
