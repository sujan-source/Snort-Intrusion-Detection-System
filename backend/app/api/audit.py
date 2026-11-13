from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from app.core.db import get_db
from app.models.audit_log import AuditLog
from app.schemas.schemas import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["Audit Trail"])

@router.get("", response_model=List[AuditLogOut])
def get_audit_logs(limit: int = 50, db: Session = Depends(get_db)):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
