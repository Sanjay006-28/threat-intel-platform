import json
import ipaddress
from fastapi import APIRouter, Request, Depends, Response, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone

from app.database import get_db
from app.models import IOC, Alert, LogFile, Feed, FeedRun, IOCSource, LogEvent, Incident
from app.enrichment import enrich_ioc, enrich_ip
from app.correlator import extract_endpoint_identity
from app.stix import export_to_stix21, import_stix21_bundle
from app.notifications import send_alert_webhook
from app.config import settings
from app.audit import log_audit
from app.crypto import get_active_webhook_url

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    # ── 1. IOC Metrics ──
    total_iocs = db.query(IOC).count()
    active_iocs = db.query(IOC).filter(IOC.is_active == True).count()
    active_pct = round((active_iocs / total_iocs * 100), 1) if total_iocs else 100

    # ── 2. Alert & Detection Metrics (Consistent & Mutually Verified) ──
    total_alerts = db.query(Alert).count()
    # Active alerts = Alerts currently requiring SOC attention (New unassigned or currently Investigating)
    active_alerts = db.query(Alert).filter(Alert.status.in_(["new", "investigating"])).count()
    new_alerts = db.query(Alert).filter(Alert.status == "new").count()
    investigating_alerts = db.query(Alert).filter(Alert.status == "investigating").count()
    resolved_alerts = db.query(Alert).filter(Alert.status.in_(["resolved", "closed", "false_positive"])).count()

    # Stratified severity counts across all active detections (Sums exactly to active_alerts)
    critical_alerts = db.query(Alert).filter(Alert.status.in_(["new", "investigating"]), Alert.severity == "critical").count()
    high_alerts = db.query(Alert).filter(Alert.status.in_(["new", "investigating"]), Alert.severity == "high").count()
    medium_alerts = db.query(Alert).filter(Alert.status.in_(["new", "investigating"]), Alert.severity == "medium").count()
    low_alerts = db.query(Alert).filter(Alert.status.in_(["new", "investigating"]), Alert.severity == "low").count()

    # ── 3. Incident Cases ──
    open_incidents = db.query(Incident).filter(Incident.is_deleted == False, Incident.status.in_(["open", "investigating"])).count()
    total_incidents = db.query(Incident).filter(Incident.is_deleted == False).count()

    # ── 4. Telemetry & Log Ingestion ──
    logs_ingested = db.query(LogFile).count()
    total_lines = db.query(func.sum(LogFile.line_count)).scalar() or 0

    # ── 5. System Timestamps & Telemetry Freshness ──
    now_utc_dt = datetime.now(timezone.utc)
    now_utc_str = now_utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    latest_log_time = db.query(func.max(LogFile.uploaded_at)).scalar()
    latest_feed_sync_time = db.query(func.max(Feed.last_run_at)).scalar()
    latest_detection_time = db.query(func.max(Alert.created_at)).scalar()

    # Distinguish running watcher daemon from actual log stream freshness
    freshness_threshold_hours = getattr(settings, "LOG_FRESHNESS_THRESHOLD_HOURS", 24)
    is_telemetry_stale = False
    telemetry_freshness_label = "NO INGESTION"
    telemetry_freshness_badge = "secondary"
    telemetry_stale_warning = "No security logs have been ingested into the platform yet."

    if latest_log_time:
        log_time_utc = latest_log_time.replace(tzinfo=timezone.utc) if latest_log_time.tzinfo is None else latest_log_time
        age_seconds = (now_utc_dt - log_time_utc).total_seconds()
        age_hours = age_seconds / 3600.0
        age_days = age_seconds / 86400.0

        if age_hours > freshness_threshold_hours:
            is_telemetry_stale = True
            if age_days >= 1:
                telemetry_freshness_label = f"STALE ({int(age_days)}d ago)"
            else:
                telemetry_freshness_label = f"STALE ({int(age_hours)}h ago)"
            telemetry_freshness_badge = "warning"
            telemetry_stale_warning = f"Warning: The most recent log ingestion occurred {int(age_days) if age_days >= 1 else int(age_hours)} {'days' if age_days >= 1 else 'hours'} ago, exceeding the {freshness_threshold_hours}h threshold. Watcher is actively polling ./auto_ingest, but no fresh log stream has been received."
        else:
            is_telemetry_stale = False
            telemetry_freshness_label = f"FRESH (<{freshness_threshold_hours}h)"
            telemetry_freshness_badge = "success"
            telemetry_stale_warning = None

    # ── 6. Threat Vector Distribution ──
    type_counts_raw = db.query(IOC.type, func.count(IOC.id)).group_by(IOC.type).order_by(func.count(IOC.id).desc()).all()
    ioc_types_labels = [t[0].upper() for t in type_counts_raw]
    ioc_types_data = [t[1] for t in type_counts_raw]

    # ── 7. Detailed Threat Feed Status Cards ──
    feed_records = db.query(Feed).all()
    feed_summary = []
    has_otx_key = bool(settings.OTX_API_KEY and settings.OTX_API_KEY.strip() and "your_otx" not in settings.OTX_API_KEY.lower())

    for f in feed_records:
        stored_count = db.query(func.count(func.distinct(IOCSource.ioc_id))).filter(IOCSource.feed_name == f.name).scalar() or 0
        last_run = db.query(FeedRun).filter(FeedRun.feed_id == f.id).order_by(FeedRun.id.desc()).first()
        
        is_otx = (f.name == "AlienVault_OTX")
        if is_otx and not has_otx_key:
            config_status = "Unconfigured (No OTX_API_KEY in .env - Optional Feed)"
            status_badge = "UNCONFIGURED (OPTIONAL)"
            badge_class = "warning"
        elif not f.enabled:
            config_status = "Disabled by Policy"
            status_badge = "DISABLED"
            badge_class = "secondary"
        elif f.last_run_status == "failed":
            config_status = "Connection Failed"
            status_badge = "FAILED"
            badge_class = "danger"
        elif stored_count == 0:
            config_status = "Connected (0 Indicators Stored)"
            status_badge = "ZERO IOCS"
            badge_class = "info"
        else:
            config_status = "Operational / Synchronized"
            status_badge = "OPERATIONAL"
            badge_class = "success"

        feed_summary.append({
            "id": f.id,
            "name": f.name,
            "type": f.type,
            "interval_minutes": f.interval_minutes,
            "enabled": f.enabled,
            "config_status": config_status,
            "status_badge": status_badge,
            "badge_class": badge_class,
            "stored_count": stored_count,
            "last_run_at": f.last_run_at,
            "last_run_str": f.last_run_at.strftime("%Y-%m-%d %H:%M UTC") if f.last_run_at else "Never",
            "new_records": last_run.new_records if last_run else 0,
            "updated_records": last_run.updated_records if last_run else 0,
            "error_message": last_run.error_message if last_run else None
        })

    operational_feeds_count = sum(1 for f in feed_summary if f["status_badge"] == "OPERATIONAL")
    unconfigured_feeds_count = sum(1 for f in feed_summary if f["status_badge"] in ["UNCONFIGURED (OPTIONAL)", "OPTIONAL / NO KEY", "ZERO IOCS", "DISABLED", "FAILED"])

    # ── 8. Recent Detections with Endpoint Identity & Validated Scores ──
    recent_alerts_raw = db.query(Alert).order_by(Alert.id.desc()).limit(12).all()
    recent_alerts = []
    threat_map_markers = []
    seen_map_coords = set()

    for a in recent_alerts_raw:
        endpoint = extract_endpoint_identity(a.log_event, a.matched_value) if a.log_event else "Internal Network (Edge/Proxy)"
        event_time = a.last_seen or a.first_seen or a.created_at
        recent_alerts.append({
            "alert": a,
            "endpoint": endpoint,
            "score": min(100, max(0, a.score or 0)),
            "event_time_str": event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if event_time else "--",
            "is_aggregated": (a.hit_count or 1) > 1
        })

        # Pre-populate map markers for public routable IPs
        val = a.matched_value.strip()
        if a.matched_type in ["ipv4", "ipv6", "ip"]:
            try:
                ip_obj = ipaddress.ip_address(val)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast):
                    enc = enrich_ip(val, skip_rdns=True)
                    lat = enc.get("lat", 0.0)
                    lon = enc.get("lon", 0.0)
                    if lat != 0.0 or lon != 0.0:
                        ckey = f"{round(lat, 2)}-{round(lon, 2)}"
                        if ckey not in seen_map_coords:
                            seen_map_coords.add(ckey)
                            threat_map_markers.append({
                                "alert_id": a.id,
                                "lat": lat,
                                "lon": lon,
                                "indicator": val,
                                "type": a.matched_type,
                                "severity": a.severity,
                                "score": min(100, max(0, a.score or 0)),
                                "country": enc.get("country", "Unknown"),
                                "city": enc.get("city", "Unknown"),
                                "org": enc.get("org", "Unknown"),
                                "hit_count": a.hit_count or 1
                            })
            except ValueError:
                pass

    # ── 9. Recent Incidents & Logs ──
    recent_incidents = db.query(Incident).filter(Incident.is_deleted == False).order_by(Incident.id.desc()).limit(5).all()
    recent_logs = db.query(LogFile).order_by(LogFile.id.desc()).limit(5).all()

    current_user = request.session.get("user", "Analyst")

    context = {
        "request": request,
        "current_user": current_user,
        # IOC KPIs
        "total_iocs": total_iocs,
        "active_iocs": active_iocs,
        "active_pct": active_pct,
        # Alert KPIs
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "new_alerts": new_alerts,
        "investigating_alerts": investigating_alerts,
        "resolved_alerts": resolved_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        # Incidents & Telemetry
        "open_incidents": open_incidents,
        "total_incidents": total_incidents,
        "logs_ingested": logs_ingested,
        "total_lines": total_lines,
        # Timestamps & Freshness
        "now_utc": now_utc_str,
        "latest_log_time_str": latest_log_time.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_log_time else "None",
        "latest_feed_sync_time_str": latest_feed_sync_time.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_feed_sync_time else "None",
        "latest_detection_time_str": latest_detection_time.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_detection_time else "None",
        "is_telemetry_stale": is_telemetry_stale,
        "telemetry_freshness_label": telemetry_freshness_label,
        "telemetry_freshness_badge": telemetry_freshness_badge,
        "telemetry_stale_warning": telemetry_stale_warning,
        "freshness_threshold_hours": freshness_threshold_hours,
        # Charts Data
        "ioc_types_labels": ioc_types_labels,
        "ioc_types_data": ioc_types_data,
        "severity_data": [critical_alerts, high_alerts, medium_alerts, low_alerts],
        # Feeds & Tables
        "feed_summary": feed_summary,
        "operational_feeds_count": operational_feeds_count,
        "unconfigured_feeds_count": unconfigured_feeds_count,
        "threat_map_markers": threat_map_markers,
        "recent_alerts": recent_alerts,
        "recent_incidents": recent_incidents,
        "recent_logs": recent_logs
    }
    return templates.TemplateResponse(request=request, name="dashboard.html", context=context)

@router.get("/api/threat-map")
def get_threat_map_data(db: Session = Depends(get_db)):
    """
    Returns authentic geo-coordinates for active public IP threats to plot on the Leaflet map.
    Strictly avoids private RFC1918 IPs and does NOT generate synthetic or fake locations.
    """
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(50).all()
    markers = []
    seen_coords = set()

    for a in alerts:
        val = a.matched_value.strip()
        # Only geolocate authentic IP addresses (do not invent coordinates for unresolvable domains or hashes)
        if a.matched_type in ["ipv4", "ipv6", "ip"]:
            try:
                ip_obj = ipaddress.ip_address(val)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
                    continue # Skip non-routable / intranet addresses
            except ValueError:
                continue

            # Real TLS GeoIP lookup without blocking reverse DNS
            enc = enrich_ip(val, skip_rdns=True)
            lat = enc.get("lat", 0.0)
            lon = enc.get("lon", 0.0)
            country = enc.get("country", "Unknown")
            city = enc.get("city", "Unknown")
            org = enc.get("org", "Unknown")

            if lat != 0.0 or lon != 0.0:
                coord_key = f"{round(lat, 2)}-{round(lon, 2)}"
                if coord_key not in seen_coords:
                    seen_coords.add(coord_key)
                    markers.append({
                        "alert_id": a.id,
                        "lat": lat,
                        "lon": lon,
                        "indicator": val,
                        "type": a.matched_type,
                        "severity": a.severity,
                        "score": min(100, max(0, a.score or 0)),
                        "country": country,
                        "city": city,
                        "org": org,
                        "hit_count": a.hit_count or 1
                    })

    return JSONResponse(content={"markers": markers, "count": len(markers)})

@router.get("/api/stix/export")
def export_stix(db: Session = Depends(get_db)):
    """Exports active, non-expired threat indicators as an OASIS STIX 2.1 compliant JSON bundle."""
    now = datetime.now(timezone.utc)
    iocs = db.query(IOC).filter(
        IOC.is_active == True,
        (IOC.expires_at == None) | (IOC.expires_at > now)
    ).limit(2000).all()
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
    """Sends a sample test webhook notification with SSRF and DNS rebinding protection."""
    if not request.session.get("user"):
        return JSONResponse(status_code=401, content={"success": False, "message": "Authentication required."})

    try:
        data = await request.json() if request.headers.get("content-type") == "application/json" else {}
    except Exception:
        data = {}

    req_url = (data.get("url") or "").strip()
    if not req_url or "********" in req_url:
        target_url = get_active_webhook_url()
    else:
        target_url = req_url

    if not target_url:
        return JSONResponse(content={"success": False, "message": "No webhook destination configured or provided."})
    
    success, msg = send_alert_webhook(
        alert_id=999,
        matched_value="185.220.101.5",
        matched_type="ipv4",
        severity="critical",
        score=95,
        webhook_url=target_url
    )
    return JSONResponse(content={"success": success, "message": msg})
