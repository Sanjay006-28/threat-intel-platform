from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database import get_db
from app.models import Alert, IOC, LogEvent, Whitelist, Incident
from app.mitre import get_mitre_mapping
from app.enrichment import enrich_ioc
from app.remediation import generate_remediation_rules
from app.scoring import explain_score
from app.audit import log_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/alerts")
def list_alerts(request: Request, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(100).all()
    incidents = db.query(Incident).filter(Incident.status != "closed").all()
    
    # Fast lightweight enrichment summary for list view without blocking requests
    enriched_alerts = []
    for alert in alerts:
        ioc = alert.ioc
        tags = ioc.tags if ioc and ioc.tags else []
        desc = ioc.description if ioc else ""
        mitre_info = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type)

        enriched_alerts.append({
            "alert": alert,
            "mitre": mitre_info[0] if mitre_info else None,
            "all_mitre": mitre_info
        })

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "request": request, 
            "enriched_alerts": enriched_alerts,
            "incidents": incidents,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.get("/alerts/{alert_id}")
def alert_detail(request: Request, alert_id: int, db: Session = Depends(get_db)):
    """Comprehensive alert investigation page."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    ioc = alert.ioc
    log_event = alert.log_event
    tags = ioc.tags if ioc and ioc.tags else []
    desc = ioc.description if ioc else ""

    mitre_list = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type)
    enrichment = enrich_ioc(alert.matched_type, alert.matched_value)
    remediation = generate_remediation_rules(alert.matched_type, alert.matched_value, alert.id)
    score_breakdown = explain_score(
        ioc_confidence=ioc.confidence if ioc else 50,
        source_count=len(ioc.sources) if ioc and ioc.sources else 1,
        ioc_type=alert.matched_type,
        hit_count=alert.hit_count or 1
    )
    incidents = db.query(Incident).filter(Incident.status != "closed").all()

    # Query recent individual log event occurrences matching this indicator for aggregated evidence audit
    related_events = (
        db.query(LogEvent)
        .filter(LogEvent.raw_line.contains(alert.matched_value))
        .order_by(LogEvent.id.desc())
        .limit(10)
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="alert_detail.html",
        context={
            "request": request,
            "alert": alert,
            "ioc": ioc,
            "log_event": log_event,
            "related_events": related_events,
            "mitre_list": mitre_list,
            "enrichment": enrichment,
            "remediation": remediation,
            "score_breakdown": score_breakdown,
            "incidents": incidents,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.get("/alerts/{alert_id}/remediation")
def get_remediation(request: Request, alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
    log_audit(db, user, "remediation_inspected", f"Viewed containment rules for Alert #{alert_id}", client_ip)

    rules = generate_remediation_rules(alert.matched_type, alert.matched_value, alert.id)
    return rules

@router.get("/alerts/{alert_id}/report", response_class=HTMLResponse)
def get_incident_report(request: Request, alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    ioc = alert.ioc
    log_event = alert.log_event
    tags = ioc.tags if ioc and ioc.tags else []
    desc = ioc.description if ioc else ""

    mitre_list = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type)
    enrichment = enrich_ioc(alert.matched_type, alert.matched_value)
    remediation = generate_remediation_rules(alert.matched_type, alert.matched_value, alert.id)

    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
    log_audit(db, user, "incident_report_generated", f"Generated incident report for Alert #{alert_id}", client_ip)

    return templates.TemplateResponse(
        request=request,
        name="incident_report.html",
        context={
            "request": request,
            "alert": alert,
            "ioc": ioc,
            "log_event": log_event,
            "mitre_list": mitre_list,
            "enrichment": enrichment,
            "remediation": remediation,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "current_user": user
        }
    )

@router.post("/alerts/{alert_id}/status")
def update_alert_status(
    request: Request,
    alert_id: int,
    status: str = Form(...),
    analyst_note: str = Form(None),
    suppress_ioc: bool = Form(False),
    incident_id: int = Form(None),
    db: Session = Depends(get_db)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    old_status = alert.status
    alert.status = status.lower()
    if analyst_note is not None:
        alert.analyst_note = analyst_note.strip()
    
    if incident_id is not None:
        alert.incident_id = incident_id if incident_id > 0 else None

    # False positive suppression feedback loop
    if status.lower() == "false_positive" and suppress_ioc:
        # Check if already in whitelist
        existing_wl = db.query(Whitelist).filter(Whitelist.value == alert.matched_value).first()
        if not existing_wl:
            wl = Whitelist(
                type=alert.matched_type,
                value=alert.matched_value,
                description=f"Suppressed via Alert #{alert_id} triage",
                reason=analyst_note or "Marked as false positive by analyst",
                created_at=datetime.now(timezone.utc)
            )
            db.add(wl)
            
        # Deactivate IOC so future logs do not alert
        if alert.ioc:
            alert.ioc.is_active = False
            log_audit(db, user, "ioc_deactivated_fp", f"Deactivated IOC [{alert.matched_value}] due to false positive triage", client_ip)

    db.commit()
    log_audit(db, user, "alert_status_updated", f"Alert #{alert_id} status changed from '{old_status}' to '{alert.status}'", client_ip)
    return RedirectResponse(url="/alerts", status_code=303)
