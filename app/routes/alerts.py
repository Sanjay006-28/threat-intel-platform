from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Alert, IOC, LogEvent
from app.mitre import get_mitre_mapping
from app.enrichment import enrich_ioc
from app.remediation import generate_remediation_rules
from datetime import datetime, timezone

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/alerts")
def list_alerts(request: Request, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(100).all()
    
    # Attach MITRE and Enrichment tags dynamically
    enriched_alerts = []
    for alert in alerts:
        ioc = alert.ioc
        tags = ioc.tags if ioc and ioc.tags else []
        desc = ioc.description if ioc else ""
        mitre_info = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type)
        
        enrichment = None
        if alert.matched_type in ["ipv4", "ipv6", "ip", "domain"]:
            enrichment = enrich_ioc(alert.matched_type, alert.matched_value)

        enriched_alerts.append({
            "alert": alert,
            "mitre": mitre_info[0] if mitre_info else None,
            "all_mitre": mitre_info,
            "enrichment": enrichment
        })

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={"request": request, "enriched_alerts": enriched_alerts}
    )

@router.get("/alerts/{alert_id}/remediation")
def get_remediation(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

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
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }
    )

@router.post("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    status: str = Form(...),
    analyst_note: str = Form(None),
    db: Session = Depends(get_db)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = status
    if analyst_note is not None:
        alert.analyst_note = analyst_note
    db.commit()
    return RedirectResponse(url="/alerts", status_code=303)
