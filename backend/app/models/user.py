from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.core.db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="analyst") # "admin" or "analyst"
    created_at = Column(DateTime, default=datetime.utcnow)
