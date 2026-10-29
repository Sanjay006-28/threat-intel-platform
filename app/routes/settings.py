from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Whitelist
from app.config import settings
from app.notifications import send_alert_webhook

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    whitelist = db.query(Whitelist).all()
    current_webhook = request.session.get("webhook_url", settings.ALERT_WEBHOOK_URL)
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "whitelist": whitelist,
            "webhook_url": current_webhook
        }
    )

@router.post("/settings/webhook")
def save_webhook(request: Request, webhook_url: str = Form(...)):
    clean_url = webhook_url.strip()
    request.session["webhook_url"] = clean_url
    settings.ALERT_WEBHOOK_URL = clean_url
    return RedirectResponse(url="/settings?webhook_saved=1", status_code=303)

@router.post("/settings/whitelist/add")
def add_whitelist(request: Request, type: str = Form(...), value: str = Form(...), description: str = Form(""), db: Session = Depends(get_db)):
    if not db.query(Whitelist).filter(Whitelist.value == value).first():
        entry = Whitelist(type=type, value=value, description=description)
        db.add(entry)
        db.commit()
    return RedirectResponse(url="/settings", status_code=303)

@router.post("/settings/whitelist/remove/{id}")
def remove_whitelist(request: Request, id: int, db: Session = Depends(get_db)):
    entry = db.query(Whitelist).filter(Whitelist.id == id).first()
    if entry:
        db.delete(entry)
        db.commit()
    return RedirectResponse(url="/settings", status_code=303)
