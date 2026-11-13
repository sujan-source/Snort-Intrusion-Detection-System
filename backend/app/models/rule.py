from sqlalchemy import Column, Integer, String, Boolean, Text
from app.core.db import Base

class SnortRule(Base):
    __tablename__ = "snort_rules"

    id = Column(Integer, primary_key=True, index=True)
    sid = Column(Integer, unique=True, index=True, nullable=False)
    rev = Column(Integer, default=1)
    msg = Column(String, nullable=False)
    protocol = Column(String, nullable=False) # tcp, udp, icmp, ip
    src_net = Column(String, default="any")
    src_port = Column(String, default="any")
    dst_net = Column(String, default="any")
    dst_port = Column(String, default="any")
    action = Column(String, default="alert") # alert, log, pass, drop
    category = Column(String, default="attempted-recon")
    severity = Column(String, default="Medium")
    raw_rule = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
