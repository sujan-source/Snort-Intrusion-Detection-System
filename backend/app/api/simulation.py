from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.schemas.schemas import SimulationTrigger, AlertOut
from app.services.simulator import generate_simulated_alert, ATTACK_PRESETS
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/simulation", tags=["Lab Attack Simulation"])

@router.get("/presets")
def get_attack_presets():
    return [
        {"key": k, "name": v["msg"], "type": v["attack_type"], "severity": v["severity"]}
        for k, v in ATTACK_PRESETS.items()
    ]

@router.post("/trigger", response_model=AlertOut)
def trigger_lab_attack(sim_in: SimulationTrigger, db: Session = Depends(get_db)):
    if sim_in.attack_type not in ATTACK_PRESETS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack_type. Must be one of: {list(ATTACK_PRESETS.keys())}"
        )
        
    alert = generate_simulated_alert(
        db=db,
        attack_key=sim_in.attack_type,
        target_ip=sim_in.target_ip,
        source_ip=sim_in.source_ip
    )
    
    # Audit log
    audit = AuditLog(
        username="lab_simulator",
        action="ATTACK_SIMULATION",
        details=f"Simulated attack '{sim_in.attack_type}' against target {sim_in.target_ip} from source {sim_in.source_ip}.",
        ip_address="127.0.0.1"
    )
    db.add(audit)
    db.commit()

    return alert
