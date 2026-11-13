from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.db import get_db
from app.models.rule import SnortRule
from app.schemas.schemas import RuleOut, RuleCreate
from app.api.auth import get_current_user
from app.models.user import User
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/rules", tags=["Snort Rules"])

@router.get("", response_model=List[RuleOut])
def list_snort_rules(db: Session = Depends(get_db)):
    return db.query(SnortRule).order_by(SnortRule.sid.asc()).all()

@router.post("", response_model=RuleOut)
def create_snort_rule(
    rule_in: RuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only administrators can manage Snort rules")
        
    existing = db.query(SnortRule).filter(SnortRule.sid == rule_in.sid).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Snort rule with SID {rule_in.sid} already exists")
        
    rule = SnortRule(**rule_in.dict())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    
    # Audit log entry
    audit = AuditLog(
        username=current_user.username,
        action="RULE_CREATE",
        details=f"Created new Snort rule SID:{rule.sid} - {rule.msg}",
        ip_address="127.0.0.1"
    )
    db.add(audit)
    db.commit()

    return rule

@router.post("/{rule_id}/toggle", response_model=RuleOut)
def toggle_snort_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only administrators can modify Snort rules")
        
    rule = db.query(SnortRule).filter(SnortRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    rule.is_active = not rule.is_active
    db.commit()
    db.refresh(rule)
    
    # Audit log entry
    audit = AuditLog(
        username=current_user.username,
        action="RULE_TOGGLE",
        details=f"Toggled Snort rule SID:{rule.sid} active state to {rule.is_active}",
        ip_address="127.0.0.1"
    )
    db.add(audit)
    db.commit()
    
    return rule
