import logging
from typing import Optional
from urllib.parse import quote_plus
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Feed, FeedRun
from app.config import settings
from app.audit import log_audit
from app.collectors.runner import (
    run_all_collectors,
    sync_single_feed,
    recover_stuck_feed_runs,
    is_feed_syncing,
    is_any_sync_running
)

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def format_utc_timestamp(dt: Optional[datetime]) -> str:
    """Formats a datetime to readable UTC string without microseconds."""
    if not dt:
        return "--"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def format_duration(start_time: datetime, end_time: Optional[datetime]) -> str:
    """Computes human-readable duration between start and end times."""
    if not end_time or not start_time:
        return "--"
    diff = (end_time - start_time).total_seconds()
    if diff < 0:
        return "0.0s"
    if diff < 1.0:
        return f"{int(diff * 1000)}ms"
    if diff < 60.0:
        return f"{diff:.2f}s"
    mins = int(diff // 60)
    secs = int(diff % 60)
    return f"{mins}m {secs}s"

@router.get("/feeds")
def list_feeds(request: Request, db: Session = Depends(get_db)):
    # 1. Recover any abandoned runs from crashes or worker interruptions
    recover_stuck_feed_runs(db)

    # 2. Query feeds in consistent order
    feeds = db.query(Feed).order_by(Feed.id.asc()).all()

    # 3. Enrich feeds with configuration status & display badges
    enriched_feeds = []
    operational_count = 0
    unconfigured_count = 0

    for feed in feeds:
        is_otx = (feed.name == "AlienVault_OTX")
        otx_unconfigured = is_otx and (not settings.OTX_API_KEY or "your_otx" in settings.OTX_API_KEY.lower())

        if otx_unconfigured:
            unconfigured_count += 1
            config_status = "NOT CONFIGURED – OPTIONAL"
            config_badge = "bg-secondary"
            enabled_display = "OPTIONAL"
            enabled_badge = "bg-secondary"
            last_run_display = "UNCONFIGURED"
            last_run_badge = "bg-secondary"
            is_operational = False
            can_sync = False
        elif not feed.enabled:
            config_status = "DISABLED"
            config_badge = "bg-warning text-dark"
            enabled_display = "NO"
            enabled_badge = "bg-secondary"
            last_run_display = (feed.last_run_status or "NEVER RUN").upper()
            last_run_badge = "bg-secondary"
            is_operational = False
            can_sync = True
        else:
            operational_count += 1
            is_operational = True
            can_sync = True
            last_status = (feed.last_run_status or "never").lower()

            if last_status == "failed":
                config_status = "SYNCHRONIZATION FAILURE"
                config_badge = "bg-danger"
                last_run_display = "FAILED"
                last_run_badge = "bg-danger"
            elif last_status == "processing":
                config_status = "PROCESSING"
                config_badge = "bg-warning text-dark"
                last_run_display = "PROCESSING"
                last_run_badge = "bg-warning text-dark"
            elif last_status == "skipped":
                config_status = "SKIPPED"
                config_badge = "bg-secondary"
                last_run_display = "SKIPPED"
                last_run_badge = "bg-secondary"
            else:
                config_status = "ENABLED & CONFIGURED"
                config_badge = "bg-info text-dark"
                last_run_display = "SUCCESS" if last_status == "success" else (feed.last_run_status or "NEVER RUN").upper()
                last_run_badge = "bg-success" if last_status == "success" else "bg-secondary"

            enabled_display = "YES"
            enabled_badge = "bg-success"

        enriched_feeds.append({
            "id": feed.id,
            "name": feed.name,
            "type": feed.type.upper() if feed.type else "API",
            "enabled": feed.enabled,
            "enabled_display": enabled_display,
            "enabled_badge": enabled_badge,
            "config_status": config_status,
            "config_badge": config_badge,
            "last_run_status": feed.last_run_status,
            "last_run_display": last_run_display,
            "last_run_badge": last_run_badge,
            "last_run_at_str": format_utc_timestamp(feed.last_run_at),
            "last_successful_sync_str": format_utc_timestamp(feed.last_successful_sync),
            "is_operational": is_operational,
            "can_sync": can_sync,
            "is_syncing": is_feed_syncing(feed.id)
        })

    # 4. Query recent runs
    recent_runs = db.query(FeedRun).order_by(FeedRun.id.desc()).limit(20).all()
    enriched_runs = []
    for r in recent_runs:
        run_status = (r.status or "unknown").lower()
        if run_status == "success":
            badge_class = "bg-success"
        elif run_status == "failed":
            badge_class = "bg-danger"
        elif run_status == "processing":
            badge_class = "bg-warning text-dark"
        elif run_status == "skipped":
            badge_class = "bg-secondary"
        else:
            badge_class = "bg-secondary"

        enriched_runs.append({
            "id": r.id,
            "feed_id": r.feed_id,
            "feed_name": r.feed.name if r.feed else f"Feed #{r.feed_id}",
            "status": run_status.upper(),
            "badge_class": badge_class,
            "start_time_str": format_utc_timestamp(r.start_time),
            "end_time_str": format_utc_timestamp(r.end_time),
            "duration_str": format_duration(r.start_time, r.end_time),
            "records_fetched": r.records_fetched or 0,
            "new_records": r.new_records or 0,
            "updated_records": r.updated_records or 0,
            "duplicate_records": getattr(r, "duplicate_records", 0) or 0,
            "error_message": r.error_message
        })

    return templates.TemplateResponse(
        request=request,
        name="feeds.html",
        context={
            "request": request,
            "feeds": enriched_feeds,
            "runs": enriched_runs,
            "operational_count": operational_count,
            "unconfigured_count": unconfigured_count,
            "total_runs_count": len(enriched_runs),
            "is_global_syncing": is_any_sync_running(),
            "msg": request.query_params.get("msg"),
            "msg_type": request.query_params.get("msg_type", "info"),
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.post("/feeds/run_all")
def trigger_all_feeds(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    if is_any_sync_running():
        msg = "Synchronization is already active. Concurrent sync prevented."
        return RedirectResponse(url=f"/feeds?msg={quote_plus(msg)}&msg_type=warning", status_code=303)

    summary = run_all_collectors(db)
    log_audit(db, user, "feeds_sync_all", f"Executed manual sync of all feeds: {summary.get('new_records', 0)} new IOCs", client_ip)

    msg = f"Sync All complete: {summary.get('success', 0)} operational feeds synchronized, {summary.get('skipped', 0)} optional skipped. " \
          f"{summary.get('new_records', 0)} new indicators, {summary.get('updated_records', 0)} refreshed."
    return RedirectResponse(url=f"/feeds?msg={quote_plus(msg)}&msg_type=success", status_code=303)

@router.post("/feeds/{feed_id}/sync")
def trigger_single_feed(request: Request, feed_id: int, db: Session = Depends(get_db)):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    feed = db.query(Feed).filter(Feed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    if is_feed_syncing(feed.id):
        msg = f"Synchronization for '{feed.name}' is already actively running."
        return RedirectResponse(url=f"/feeds?msg={quote_plus(msg)}&msg_type=warning", status_code=303)

    res = sync_single_feed(feed.id, db=db)
    res_status = res.get("status")

    if res_status == "success":
        msg = f"Feed '{feed.name}' synchronized successfully: {res.get('records_fetched', 0)} fetched, " \
              f"{res.get('new_records', 0)} new, {res.get('updated_records', 0)} refreshed, " \
              f"{res.get('duplicate_records', 0)} duplicate."
        msg_type = "success"
    elif res_status == "skipped":
        msg = f"Feed '{feed.name}' skipped: {res.get('message')}"
        msg_type = "secondary"
    elif res_status == "busy":
        msg = res.get("message", "Feed sync already in progress.")
        msg_type = "warning"
    else:
        msg = f"Feed '{feed.name}' sync failed: {res.get('message')}"
        msg_type = "danger"

    log_audit(db, user, "feed_sync_single", f"Manual sync of {feed.name}: {res_status}", client_ip)
    return RedirectResponse(url=f"/feeds?msg={quote_plus(msg)}&msg_type={msg_type}", status_code=303)
