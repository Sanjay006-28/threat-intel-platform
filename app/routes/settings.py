import os
from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database import get_db
from app.models import Whitelist, AuditLog
from app.config import settings
from app.audit import log_audit
from app.normalizer import detect_and_normalize

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    whitelist = db.query(Whitelist).order_by(Whitelist.id.desc()).all()
    current_webhook = request.session.get("webhook_url", settings.ALERT_WEBHOOK_URL)
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "whitelist": whitelist,
            "webhook_url": current_webhook,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.post("/settings/webhook")
def save_webhook(request: Request, webhook_url: str = Form(...), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = request.session.get("user", "Analyst")
    clean_url = webhook_url.strip()
    
    request.session["webhook_url"] = clean_url
    settings.ALERT_WEBHOOK_URL = clean_url

    # Persist into .env file if it exists
    env_path = ".env"
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            found = False
            new_lines = []
            for line in lines:
                if line.startswith("ALERT_WEBHOOK_URL="):
                    new_lines.append(f"ALERT_WEBHOOK_URL={clean_url}\n")
                    found = True
                else:
                    new_lines.append(line)
            if not found:
                new_lines.append(f"ALERT_WEBHOOK_URL={clean_url}\n")
            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception:
            pass

    log_audit(db, user, "settings_webhook_updated", f"Webhook set to: {clean_url[:30]}...", client_ip)
    return RedirectResponse(url="/settings?webhook_saved=1", status_code=303)

@router.post("/settings/whitelist/add")
def add_whitelist(
    request: Request,
    type: str = Form(...),
    value: str = Form(...),
    description: str = Form(""),
    reason: str = Form(""),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = request.session.get("user", "Analyst")
    clean_val = value.strip()
    
    # Normalize before adding to whitelist
    norm_type, norm_val = detect_and_normalize(clean_val, is_feed_ioc=False)
    final_val = norm_val if norm_val else clean_val
    final_type = norm_type if norm_type else type.lower()

    if not db.query(Whitelist).filter(Whitelist.value == final_val).first():
        entry = Whitelist(
            type=final_type,
            value=final_val,
            description=description.strip(),
            reason=reason.strip() or "Manual analyst whitelist addition",
            created_at=datetime.now(timezone.utc)
        )
        db.add(entry)
        db.commit()
        log_audit(db, user, "whitelist_add", f"Added {final_type} [{final_val}] to whitelist. Reason: {reason}", client_ip)
        
    return RedirectResponse(url="/settings", status_code=303)

@router.post("/settings/whitelist/remove/{id}")
def remove_whitelist(request: Request, id: int, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = request.session.get("user", "Analyst")
    entry = db.query(Whitelist).filter(Whitelist.id == id).first()
    if entry:
        val = entry.value
        typ = entry.type
        db.delete(entry)
        db.commit()
        log_audit(db, user, "whitelist_remove", f"Removed {typ} [{val}] from whitelist", client_ip)
    return RedirectResponse(url="/settings", status_code=303)

@router.get("/audit-logs")
def audit_logs_page(request: Request, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    return templates.TemplateResponse(
        request=request,
        name="audit_logs.html",
        context={"request": request, "audit_logs": logs}
    )
