from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional
from datetime import datetime

from app.core.db import get_db
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.schemas.schemas import AlertOut, AlertPaginated, AlertStatusUpdate
from app.api.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=AlertPaginated)
def list_alerts(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    status: Optional[str] = None,
    attack_type: Optional[str] = None,
    ip: Optional[str] = None
):
    query = db.query(Alert)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Alert.msg.ilike(search_pattern),
                Alert.source_ip.ilike(search_pattern),
                Alert.destination_ip.ilike(search_pattern),
                Alert.attack_type.ilike(search_pattern),
                Alert.raw_alert.ilike(search_pattern)
            )
        )
    
    if severity:
        query = query.filter(Alert.severity.ilike(severity))
        
    if protocol:
        query = query.filter(Alert.protocol.ilike(protocol))
        
    if status:
        query = query.filter(Alert.status.ilike(status))
        
    if attack_type:
        query = query.filter(Alert.attack_type.ilike(f"%{attack_type}%"))
        
    if ip:
        query = query.filter(
            or_(
                Alert.source_ip == ip,
                Alert.destination_ip == ip
            )
        )

    total = query.count()
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    
    alerts = (
        query.order_by(Alert.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "alerts": alerts
    }

@router.get("/{alert_id}", response_model=AlertOut)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    status_update: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    valid_statuses = ["New", "Investigating", "False Positive", "Resolved"]
    if status_update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of {valid_statuses}")
        
    old_status = alert.status
    alert.status = status_update.status
    if status_update.notes:
        alert.notes = f"[{current_user.username} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}]: {status_update.notes}\n" + (alert.notes or "")
        
    db.commit()
    db.refresh(alert)
    
    # Audit log entry
    audit = AuditLog(
        username=current_user.username,
        action="ALERT_STATUS_UPDATE",
        details=f"Alert #{alert.id} status changed from '{old_status}' to '{alert.status}'.",
        ip_address="127.0.0.1"
    )
    db.add(audit)
    db.commit()
    
    return alert
