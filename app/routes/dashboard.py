import json
from fastapi import APIRouter, Request, Depends, Response, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone

from app.database import get_db
from app.models import IOC, Alert, LogFile, Feed, LogEvent, Incident
from app.enrichment import enrich_ioc
from app.stix import export_to_stix21, import_stix21_bundle
from app.notifications import send_alert_webhook
from app.config import settings
from app.audit import log_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    total_iocs = db.query(IOC).count()
    active_iocs = db.query(IOC).filter(IOC.is_active == True).count()
    open_alerts = db.query(Alert).filter(Alert.status == "new").count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "critical").count()
    high_alerts = db.query(Alert).filter(Alert.severity == "high").count()
    medium_alerts = db.query(Alert).filter(Alert.severity == "medium").count()
    low_alerts = db.query(Alert).filter(Alert.severity == "low").count()
    
    open_incidents = db.query(Incident).filter(Incident.status.in_(["open", "investigating"])).count()
    total_incidents = db.query(Incident).count()

    logs_ingested = db.query(LogFile).count()
    total_lines = db.query(func.sum(LogFile.line_count)).scalar() or 0
    
    # Real IOC type distribution
    type_counts_raw = db.query(IOC.type, func.count(IOC.id)).group_by(IOC.type).all()
    ioc_types_labels = [t[0].upper() for t in type_counts_raw]
    ioc_types_data = [t[1] for t in type_counts_raw]
    
    # Real Feed status
    feeds = db.query(Feed).all()
    
    # Recent alerts with details
    recent_alerts = db.query(Alert).order_by(Alert.id.desc()).limit(8).all()
    
    # Recent incidents
    recent_incidents = db.query(Incident).order_by(Incident.id.desc()).limit(5).all()

    # Recent log files
    recent_logs = db.query(LogFile).order_by(LogFile.id.desc()).limit(5).all()
    
    current_user = request.session.get("user", "Analyst")
    
    context = {
        "request": request,
        "current_user": current_user,
        "total_iocs": total_iocs,
        "active_iocs": active_iocs,
        "active_pct": round((active_iocs / total_iocs * 100), 1) if total_iocs else 100,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "open_incidents": open_incidents,
        "total_incidents": total_incidents,
        "logs_ingested": logs_ingested,
        "total_lines": total_lines,
        "ioc_types_labels": ioc_types_labels,
        "ioc_types_data": ioc_types_data,
        "severity_data": [critical_alerts, high_alerts, medium_alerts, low_alerts],
        "feeds": feeds,
        "recent_alerts": recent_alerts,
        "recent_incidents": recent_incidents,
        "recent_logs": recent_logs,
        "now_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    return templates.TemplateResponse(request=request, name="dashboard.html", context=context)

@router.get("/api/threat-map")
def get_threat_map_data(db: Session = Depends(get_db)):
    """Returns geo-coordinates and metadata for IP/domain alerts to plot on Leaflet map."""
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(30).all()
    markers = []
    seen_coords = set()

    fallback_coords = {
        "185.220.101.5": (51.1657, 10.4515, "Germany", "Tor Exit C2"),
        "194.26.29.112": (52.3676, 4.9041, "Netherlands", "Botnet Beacon C2"),
        "91.92.251.103": (50.8503, 4.3517, "Belgium", "AsyncRAT C2"),
        "evil-malware-download.xyz": (55.7558, 37.6173, "Russia", "Malware Payload Host"),
        "phishing-bank-login.top": (37.7749, -122.4194, "United States", "Phishing Site")
    }

    for a in alerts:
        val = a.matched_value
        lat, lon = 0.0, 0.0
        country = "Unknown"
        label = a.matched_value

        if val in fallback_coords:
            lat, lon, country, label = fallback_coords[val]
        else:
            enc = enrich_ioc(a.matched_type, a.matched_value)
            lat = enc.get("lat", 0.0)
            lon = enc.get("lon", 0.0)
            country = enc.get("country", "Unknown")

        if lat != 0.0 or lon != 0.0:
            coord_key = f"{round(lat, 2)}-{round(lon, 2)}"
            if coord_key not in seen_coords:
                seen_coords.add(coord_key)
                markers.append({
                    "alert_id": a.id,
                    "lat": lat,
                    "lon": lon,
                    "indicator": a.matched_value,
                    "type": a.matched_type,
                    "severity": a.severity,
                    "score": a.score,
                    "country": country,
                    "label": label
                })

    return JSONResponse(content={"markers": markers})

@router.get("/api/stix/export")
def export_stix(db: Session = Depends(get_db)):
    """Exports active threat indicators as an OASIS STIX 2.1 compliant JSON bundle."""
    iocs = db.query(IOC).filter(IOC.is_active == True).limit(1000).all()
    bundle = export_to_stix21(iocs)
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinel_stix21_bundle.json"}
    )

@router.post("/api/stix/import")
async def import_stix(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Imports indicators from an uploaded OASIS STIX 2.1 bundle."""
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        content = await file.read()
        bundle_data = json.loads(content.decode("utf-8"))
        stats = import_stix21_bundle(bundle_data, db)
        log_audit(db, user, "stix_imported", f"Imported STIX bundle: {stats}", client_ip)
        return JSONResponse(content={"success": True, "stats": stats})
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@router.post("/api/webhook/test")
async def test_webhook(request: Request):
    """Sends a sample test webhook notification."""
    data = await request.json() if request.headers.get("content-type") == "application/json" else {}
    target_url = data.get("url") or settings.ALERT_WEBHOOK_URL
    success = send_alert_webhook(
        alert_id=999,
        matched_value="185.220.101.5",
        matched_type="ipv4",
        severity="critical",
        score=95,
        webhook_url=target_url
    )
    return JSONResponse(content={"success": success, "message": "Notification dispatched." if success else "Webhook URL not configured or delivery failed."})
