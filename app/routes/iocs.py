import math
from fastapi import APIRouter, Request, Depends, Form, HTTPException, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from datetime import datetime, timezone, timedelta

from app.database import get_db
from app.models import IOC, IOCSource
from app.normalizer import detect_and_normalize
from app.audit import log_audit
from app.config import settings

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/iocs")
def list_iocs(
    request: Request,
    q: str = Query(None),
    type: str = Query(None),
    status: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    db: Session = Depends(get_db)
):
    query = db.query(IOC)
    
    if q:
        clean_q = q.strip().lower()
        query = query.filter(
            or_(
                IOC.value.like(f"%{clean_q}%"),
                IOC.description.like(f"%{clean_q}%")
            )
        )
        
    if type and type != "all":
        query = query.filter(IOC.type == type.lower())
        
    if status == "active":
        query = query.filter(IOC.is_active == True)
    elif status == "inactive":
        query = query.filter(IOC.is_active == False)
        
    total_count = query.count()
    total_pages = max(1, math.ceil(total_count / page_size))
    page = min(page, total_pages)
    
    iocs = query.order_by(IOC.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    
    # Types list for filter dropdown
    available_types = [r[0] for r in db.query(IOC.type).distinct().all() if r[0]]
    
    return templates.TemplateResponse(
        request=request,
        name="iocs.html",
        context={
            "request": request,
            "iocs": iocs,
            "total_count": total_count,
            "current_page": page,
            "total_pages": total_pages,
            "page_size": page_size,
            "search_query": q or "",
            "selected_type": type or "all",
            "selected_status": status or "all",
            "available_types": available_types,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.get("/iocs/{ioc_id}")
def view_ioc(request: Request, ioc_id: int, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    return templates.TemplateResponse(
        request=request,
        name="ioc_detail.html",
        context={
            "request": request,
            "ioc": ioc,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.post("/iocs/create")
def create_ioc(
    request: Request,
    value: str = Form(...),
    type: str = Form(None),
    confidence: int = Form(75),
    severity: str = Form("medium"),
    tags: str = Form(""),
    description: str = Form(""),
    db: Session = Depends(get_db)
):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_val = value.strip()
    
    # Normalize indicator
    norm_type, norm_val = detect_and_normalize(clean_val, is_feed_ioc=False)
    final_type = norm_type or (type.lower() if type else "domain")
    final_val = norm_val or clean_val

    tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]

    existing = db.query(IOC).filter(IOC.value == final_val).first()
    if existing:
        existing.is_active = True
        existing.confidence = max(existing.confidence, confidence)
        existing.last_seen = datetime.now(timezone.utc)
        db.commit()
        log_audit(db, user, "ioc_reactivated", f"Reactivated existing IOC: {final_val}", client_ip)
        return RedirectResponse(url=f"/iocs/{existing.id}", status_code=303)

    new_ioc = IOC(
        type=final_type,
        value=final_val,
        confidence=max(0, min(100, confidence)),
        severity=severity.lower(),
        tags=tag_list,
        description=description.strip() or f"Manually added indicator by {user}",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.IOC_TTL_DAYS),
        is_active=True
    )
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)
    
    # Add manual attribution source
    manual_source = IOCSource(
        ioc_id=new_ioc.id,
        feed_name="Manual Entry",
        reference_url=f"Added by {user}",
        seen_at=datetime.now(timezone.utc)
    )
    db.add(manual_source)
    db.commit()

    log_audit(db, user, "ioc_created", f"Created manual IOC [{final_type}] {final_val}", client_ip)
    return RedirectResponse(url=f"/iocs/{new_ioc.id}", status_code=303)

@router.post("/iocs/{ioc_id}/toggle")
def toggle_ioc_status(request: Request, ioc_id: int, db: Session = Depends(get_db)):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    ioc.is_active = not ioc.is_active
    db.commit()
    
    action = "ioc_activated" if ioc.is_active else "ioc_deactivated"
    log_audit(db, user, action, f"Toggled IOC #{ioc.id} active state to {ioc.is_active}", client_ip)
    
    return RedirectResponse(url=f"/iocs/{ioc_id}", status_code=303)
