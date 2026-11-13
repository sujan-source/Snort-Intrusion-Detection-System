from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from app.core.db import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String, nullable=False)
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String, default="127.0.0.1")
