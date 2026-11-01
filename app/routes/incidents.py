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

VALID_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

@router.get("/incidents")
def list_incidents(
    request: Request,
    tab: str = "active",
    msg: str = None,
    error: str = None,
    db: Session = Depends(get_db)
):
    active_tab = "deleted" if tab == "deleted" else "active"
    
    active_incidents = db.query(Incident).filter(Incident.is_deleted == False).order_by(Incident.id.desc()).all()
    deleted_incidents = db.query(Incident).filter(Incident.is_deleted == True).order_by(Incident.deleted_at.desc(), Incident.id.desc()).all()
    
    open_count = db.query(Incident).filter(Incident.is_deleted == False, Incident.status.in_(["open", "investigating"])).count()
    active_count = len(active_incidents)
    deleted_count = len(deleted_incidents)

    flash_msg = request.session.pop("flash_success", None) or msg
    flash_error = request.session.pop("flash_error", None) or error
    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "request": request,
            "incidents": active_incidents if active_tab == "active" else deleted_incidents,
            "active_incidents": active_incidents,
            "deleted_incidents": deleted_incidents,
            "active_tab": active_tab,
            "open_count": open_count,
            "active_count": active_count,
            "deleted_count": deleted_count,
            "flash_msg": flash_msg,
            "flash_error": flash_error,
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
def view_incident(
    request: Request,
    incident_id: int,
    error_msg: str = None,
    db: Session = Depends(get_db)
):
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
            "error_msg": error_msg,
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

    status_clean = status.lower().strip()
    severity_clean = severity.lower().strip()

    # Validation
    errors = []
    if status_clean not in VALID_STATUSES:
        errors.append(f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}.")
    if severity_clean not in VALID_SEVERITIES:
        errors.append(f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}.")

    if errors:
        error_msg = " ".join(errors)
        unassigned_alerts = db.query(Alert).filter(Alert.incident_id == None).order_by(Alert.id.desc()).limit(20).all()
        # Preserve user input in display object without saving bad data
        temp_inc = Incident(
            id=inc.id,
            title=inc.title,
            description=inc.description,
            status=status_clean if status_clean in VALID_STATUSES else inc.status,
            severity=severity_clean if severity_clean in VALID_SEVERITIES else inc.severity,
            analyst_notes=analyst_notes,
            resolution_summary=resolution_summary,
            created_at=inc.created_at,
            updated_at=inc.updated_at
        )
        return templates.TemplateResponse(
            request=request,
            name="incident_detail.html",
            context={
                "request": request,
                "incident": temp_inc,
                "alerts": inc.alerts,
                "unassigned_alerts": unassigned_alerts,
                "error_msg": error_msg,
                "current_user": user
            },
            status_code=422
        )

    # Valid update: Modify only existing record identified by its ID
    inc.status = status_clean
    inc.severity = severity_clean
    inc.analyst_notes = analyst_notes.strip()
    inc.resolution_summary = resolution_summary.strip()
    inc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inc)

    log_audit(db, user, "incident_updated", f"Updated Incident #{inc.id} status to '{inc.status}', severity to '{inc.severity}'", client_ip)

    success_msg = f"Incident #{inc.id} updated successfully."
    request.session["flash_success"] = success_msg
    return RedirectResponse(
        url=f"/incidents?msg=Incident+%23{inc.id}+updated+successfully.",
        status_code=303
    )

@router.post("/incidents/{incident_id}/delete")
def delete_incident(
    request: Request,
    incident_id: int,
    db: Session = Depends(get_db)
):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if inc.is_deleted:
        return RedirectResponse(url="/incidents?tab=deleted&msg=Incident+already+archived.", status_code=303)

    # Soft-deletion: mark as deleted, retain associations and alerts intact
    inc.is_deleted = True
    inc.deleted_at = datetime.now(timezone.utc)
    inc.deleted_by = user
    db.commit()

    log_audit(db, user, "incident_deleted", f"Soft-deleted Incident #{inc.id}: {inc.title}", client_ip)

    success_msg = f"Incident #{inc.id} deleted successfully."
    request.session["flash_success"] = success_msg
    return RedirectResponse(
        url=f"/incidents?msg=Incident+%23{inc.id}+deleted+successfully.",
        status_code=303
    )

@router.post("/incidents/{incident_id}/restore")
def restore_incident(
    request: Request,
    incident_id: int,
    db: Session = Depends(get_db)
):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not inc.is_deleted:
        return RedirectResponse(url=f"/incidents/{inc.id}?msg=Incident+is+already+active.", status_code=303)

    # Restoration: clear deletion metadata and return to active ledger
    inc.is_deleted = False
    inc.deleted_at = None
    inc.deleted_by = None
    inc.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_audit(db, user, "incident_restored", f"Restored Incident #{inc.id}: {inc.title} to active ledger", client_ip)

    success_msg = f"Incident #{inc.id} restored successfully."
    request.session["flash_success"] = success_msg
    return RedirectResponse(
        url=f"/incidents?msg=Incident+%23{inc.id}+restored+successfully.",
        status_code=303
    )

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

