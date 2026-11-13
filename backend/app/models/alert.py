from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from app.core.db import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    sid = Column(Integer, index=True)
    rev = Column(Integer, default=1)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String, index=True, nullable=False)
    destination_ip = Column(String, index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, index=True, nullable=False)
    attack_type = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False) # "Critical", "High", "Medium", "Low"
    msg = Column(String, nullable=False)
    status = Column(String, default="New", index=True) # "New", "Investigating", "False Positive", "Resolved"
    notes = Column(Text, nullable=True)
    raw_alert = Column(Text, nullable=True)
    payload_hex = Column(Text, nullable=True)
