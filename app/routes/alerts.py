from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import Optional

from app.database import get_db
from app.models import Alert, IOC, LogEvent, Whitelist, Incident
from app.mitre import get_mitre_mapping
from app.enrichment import enrich_ioc
from app.remediation import generate_remediation_rules
from app.scoring import explain_score
from app.audit import log_audit
from app.correlator import extract_endpoint_identity
from app.parsers.manager import parse_log_timestamp

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/alerts")
def list_alerts(request: Request, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(100).all()
    incidents = db.query(Incident).filter(Incident.is_deleted == False, Incident.status != "closed").all()
    
    # Fast lightweight enrichment summary for list view without blocking requests
    enriched_alerts = []
    for alert in alerts:
        ioc = alert.ioc
        tags = ioc.tags if ioc and ioc.tags else []
        desc = ioc.description if ioc else ""
        raw_log = alert.log_event.raw_line if alert.log_event else ""
        endpoint = extract_endpoint_identity(alert.log_event, alert.matched_value) if alert.log_event else "Internal Network"
        mitre_info = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type, raw_log=raw_log)

        enriched_alerts.append({
            "alert": alert,
            "mitre": mitre_info[0] if mitre_info else None,
            "all_mitre": mitre_info,
            "endpoint": endpoint
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
    raw_log = log_event.raw_line if log_event else ""

    # Endpoint identity
    endpoint = extract_endpoint_identity(log_event, alert.matched_value) if log_event else "Internal Network (Edge/Proxy)"

    # ── 1. Timestamp Precision & Provenance (Requirement 3) ──
    source_event_time = None
    if log_event and log_event.raw_line:
        source_event_time = parse_log_timestamp(log_event.raw_line)
    if not source_event_time and log_event and log_event.timestamp:
        source_event_time = log_event.timestamp

    ingestion_time = log_event.log_file.uploaded_at if (log_event and log_event.log_file) else alert.created_at
    first_seen_time = alert.first_seen or alert.created_at
    last_seen_time = alert.last_seen or alert.first_seen or alert.created_at

    # ── 2. Threat Indicator Attribution & Provenance (Requirement 4) ──
    source_names = [s.feed_name for s in ioc.sources] if (ioc and ioc.sources) else []
    ioc_tags = [str(t).lower() for t in (ioc.tags or [])] if ioc else []
    is_demonstration_ioc = any(
        s.lower() in ["samplefeed", "sample_feed", "mock", "demo", "test"] for s in source_names
    ) or any(t in ["mock", "testing", "demo", "sample", "synthetic"] for t in ioc_tags)

    if is_demonstration_ioc:
        provenance_badge = "warning"
        provenance_label = "DEMONSTRATION / SYNTHETIC IOC"
        provenance_desc = "Originates from local synthetic dataset ('SampleFeed') for controlled lab validation. Not confirmed external threat intelligence."
    else:
        provenance_badge = "success"
        provenance_label = "CONFIRMED EXTERNAL THREAT INTEL"
        provenance_desc = "Synchronized from active threat intelligence feeds (ThreatFox / URLhaus / FeodoTracker / MalwareBazaar)."

    # ── 3. Occurrence Count & Evidence History Consistency (Requirement 2) ──
    all_matching_events = (
        db.query(LogEvent)
        .filter(LogEvent.raw_line.contains(alert.matched_value))
        .order_by(LogEvent.id.desc())
        .all()
    )

    primary_event = alert.log_event
    alert_hit_count = max(1, alert.hit_count or 1)

    # Scoped strictly to this alert's aggregation group (count matches alert.hit_count)
    if alert_hit_count <= 1:
        alert_evidence_events = [primary_event] if primary_event else []
    else:
        group_events = []
        if primary_event:
            group_events.append(primary_event)
        for ev in all_matching_events:
            if primary_event and ev.id == primary_event.id:
                continue
            ev_ep = extract_endpoint_identity(ev, alert.matched_value)
            if ev_ep == endpoint and len(group_events) < alert_hit_count:
                group_events.append(ev)
        alert_evidence_events = group_events

    # Correlated events across other alerts / log files (cross-campaign evidence visibility)
    correlated_platform_events = []
    alert_event_ids = {e.id for e in alert_evidence_events if e}
    for ev in all_matching_events:
        if ev.id in alert_event_ids:
            continue
        associated_alert = db.query(Alert).filter(Alert.log_event_id == ev.id).first()
        ev_ep = extract_endpoint_identity(ev, alert.matched_value)
        ev_time = parse_log_timestamp(ev.raw_line) or (ev.timestamp if ev.timestamp else None)
        correlated_platform_events.append({
            "event": ev,
            "associated_alert": associated_alert,
            "endpoint": ev_ep,
            "timestamp": ev_time,
            "filename": ev.log_file.filename if ev.log_file else "Unknown"
        })

    # ── 4. MITRE ATT&CK Context with Evidence Attribution (Requirement 5) ──
    mitre_list = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type, raw_log=raw_log)

    # ── 5. Enrichment & Containment Rules (Requirement 6) ──
    enrichment = enrich_ioc(alert.matched_type, alert.matched_value)
    remediation = generate_remediation_rules(alert.matched_type, alert.matched_value, alert.id)
    score_breakdown = explain_score(
        ioc_confidence=ioc.confidence if ioc else 50,
        source_count=len(ioc.sources) if ioc and ioc.sources else 1,
        ioc_type=alert.matched_type,
        hit_count=alert.hit_count or 1
    )
    incidents = db.query(Incident).filter(Incident.is_deleted == False, Incident.status != "closed").all()

    return templates.TemplateResponse(
        request=request,
        name="alert_detail.html",
        context={
            "request": request,
            "alert": alert,
            "ioc": ioc,
            "log_event": log_event,
            "endpoint": endpoint,
            "source_event_time": source_event_time,
            "ingestion_time": ingestion_time,
            "first_seen_time": first_seen_time,
            "last_seen_time": last_seen_time,
            "is_demonstration_ioc": is_demonstration_ioc,
            "provenance_badge": provenance_badge,
            "provenance_label": provenance_label,
            "provenance_desc": provenance_desc,
            "alert_evidence_events": alert_evidence_events,
            "correlated_platform_events": correlated_platform_events,
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
    raw_log = log_event.raw_line if log_event else ""

    mitre_list = get_mitre_mapping(tags=tags, description=desc, ioc_type=alert.matched_type, raw_log=raw_log)
    enrichment = enrich_ioc(alert.matched_type, alert.matched_value)
    remediation = generate_remediation_rules(alert.matched_type, alert.matched_value, alert.id)

    endpoint = extract_endpoint_identity(log_event, alert.matched_value) if log_event else "Internal Network"
    source_event_time = parse_log_timestamp(log_event.raw_line) if (log_event and log_event.raw_line) else None

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
            "endpoint": endpoint,
            "source_event_time": source_event_time,
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
