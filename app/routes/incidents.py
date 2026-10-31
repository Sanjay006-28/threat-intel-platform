from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database import get_db
from app.models import Incident, Alert
from app.audit import log_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/incidents")
def list_incidents(request: Request, db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.id.desc()).all()
    open_count = db.query(Incident).filter(Incident.status.in_(["open", "investigating"])).count()
    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "request": request,
            "incidents": incidents,
            "open_count": open_count,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.post("/incidents/create")
def create_incident(
    request: Request,
    title: str = Form(...),
    severity: str = Form("medium"),
    description: str = Form(""),
    alert_id: int = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    new_inc = Incident(
        title=title.strip(),
        severity=severity.lower(),
        description=description.strip(),
        status="open",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(new_inc)
    db.commit()
    db.refresh(new_inc)

    if alert_id:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            alert.incident_id = new_inc.id
            db.commit()

    log_audit(db, user, "incident_created", f"Created Incident #{new_inc.id}: {new_inc.title}", client_ip)
    return RedirectResponse(url=f"/incidents/{new_inc.id}", status_code=303)

@router.get("/incidents/{incident_id}")
def view_incident(request: Request, incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    unassigned_alerts = db.query(Alert).filter(Alert.incident_id == None).order_by(Alert.id.desc()).limit(20).all()
    
    return templates.TemplateResponse(
        request=request,
        name="incident_detail.html",
        context={
            "request": request,
            "incident": inc,
            "alerts": inc.alerts,
            "unassigned_alerts": unassigned_alerts,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.post("/incidents/{incident_id}/update")
def update_incident(
    request: Request,
    incident_id: int,
    status: str = Form(...),
    severity: str = Form(...),
    analyst_notes: str = Form(""),
    resolution_summary: str = Form(""),
    db: Session = Depends(get_db)
):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc.status = status.lower()
    inc.severity = severity.lower()
    inc.analyst_notes = analyst_notes.strip()
    inc.resolution_summary = resolution_summary.strip()
    inc.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_audit(db, user, "incident_updated", f"Updated Incident #{inc.id} status to '{inc.status}'", client_ip)
    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)

@router.post("/incidents/{incident_id}/add_alert")
def add_alert_to_incident(
    request: Request,
    incident_id: int,
    alert_id: int = Form(...),
    db: Session = Depends(get_db)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if inc and alert:
        alert.incident_id = inc.id
        db.commit()
    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)

@router.post("/incidents/{incident_id}/remove_alert/{alert_id}")
def remove_alert_from_incident(
    request: Request,
    incident_id: int,
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.incident_id == incident_id).first()
    if alert:
        alert.incident_id = None
        db.commit()
    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)

