import math
import ipaddress
from typing import Optional
from urllib.parse import urlencode, quote_plus, urlparse
from fastapi import APIRouter, Request, Depends, Form, HTTPException, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from datetime import datetime, timezone, timedelta

from app.database import get_db
from app.models import IOC, IOCSource
from app.normalizer import detect_and_normalize, refang
from app.audit import log_audit
from app.config import settings

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/iocs")
def list_iocs(
    request: Request,
    q: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: Optional[str] = Query("1"),
    page_size: Optional[str] = Query("50"),
    db: Session = Depends(get_db)
):
    # Safe page & page_size normalization (guarantees no 422 on invalid/malformed input)
    try:
        page_num = int(page) if page is not None and str(page).strip() else 1
        if page_num < 1:
            page_num = 1
    except (ValueError, TypeError):
        page_num = 1

    try:
        size_num = int(page_size) if page_size is not None and str(page_size).strip() else 50
        if size_num < 10:
            size_num = 10
        elif size_num > 200:
            size_num = 200
    except (ValueError, TypeError):
        size_num = 50

    query = db.query(IOC)
    clean_q = q.strip() if q else ""
    
    if clean_q:
        refanged_q = refang(clean_q)
        search_terms = list(dict.fromkeys([clean_q, refanged_q]))
        
        search_clauses = []
        for term in search_terms:
            search_clauses.append(IOC.value.ilike(f"%{term}%"))
            search_clauses.append(IOC.description.ilike(f"%{term}%"))
            
        # Bidirectional CIDR / Network range correlation
        # 1. If clean_q is an IP address, find any CIDR IOCs whose network range contains this IP
        matching_cidr_ids = []
        for term in search_terms:
            try:
                ip_obj = ipaddress.ip_address(term)
                # Check CIDR indicators in database
                cidr_rows = db.query(IOC.id, IOC.value).filter(
                    or_(IOC.type == "cidr", IOC.value.like("%/%"))
                ).all()
                for c_id, c_val in cidr_rows:
                    if not c_val.startswith("http://") and not c_val.startswith("https://"):
                        try:
                            net = ipaddress.ip_network(c_val.strip(), strict=False)
                            if ip_obj in net:
                                matching_cidr_ids.append(c_id)
                        except ValueError:
                            pass
            except ValueError:
                pass
                
        # 2. If clean_q is a CIDR network, find any IP IOCs that fall within this network
        matching_ip_ids = []
        for term in search_terms:
            if "/" in term and not term.startswith("http://") and not term.startswith("https://"):
                try:
                    net_obj = ipaddress.ip_network(term, strict=False)
                    ip_rows = db.query(IOC.id, IOC.value).filter(
                        IOC.type.in_(["ipv4", "ipv6"])
                    ).all()
                    for i_id, i_val in ip_rows:
                        try:
                            if ipaddress.ip_address(i_val.strip()) in net_obj:
                                matching_ip_ids.append(i_id)
                        except ValueError:
                            pass
                except ValueError:
                    pass

        if matching_cidr_ids:
            search_clauses.append(IOC.id.in_(matching_cidr_ids))
        if matching_ip_ids:
            search_clauses.append(IOC.id.in_(matching_ip_ids))

        query = query.filter(or_(*search_clauses))

    clean_type = (type or "").strip().lower()
    if clean_type and clean_type != "all":
        query = query.filter(IOC.type == clean_type)

    clean_status = (status or "").strip().lower()
    if clean_status in ["active", "true", "1"]:
        query = query.filter(IOC.is_active.is_(True))
    elif clean_status in ["inactive", "deactivated", "expired", "false", "0"]:
        query = query.filter(IOC.is_active.is_(False))

    total_count = query.count()
    total_pages = max(1, math.ceil(total_count / size_num)) if total_count > 0 else 1
    current_page = max(1, min(page_num, total_pages)) if total_count > 0 else 1

    iocs = query.order_by(IOC.id.desc()).offset((current_page - 1) * size_num).limit(size_num).all()

    # Types list for filter dropdown (canonical types merged with stored database types)
    db_types = [r[0] for r in db.query(IOC.type).distinct().all() if r[0]]
    canonical_types = ["cidr", "domain", "email", "ipv4", "ipv6", "md5", "sha1", "sha256", "url"]
    available_types = sorted(list(set(db_types + canonical_types)))

    # Construct pagination & back-navigation URLs preserving active filters
    def make_filter_url(target_page: int) -> str:
        params = {}
        if clean_q:
            params["q"] = clean_q
        if clean_type and clean_type != "all":
            params["type"] = clean_type
        if clean_status and clean_status != "all":
            params["status"] = clean_status
        if target_page > 1:
            params["page"] = target_page
        qs = urlencode(params)
        return f"/iocs?{qs}" if qs else "/iocs"

    prev_page_url = make_filter_url(current_page - 1) if current_page > 1 else None
    next_page_url = make_filter_url(current_page + 1) if current_page < total_pages else None
    current_filter_url = make_filter_url(current_page)

    return templates.TemplateResponse(
        request=request,
        name="iocs.html",
        context={
            "request": request,
            "iocs": iocs,
            "total_count": total_count,
            "current_page": current_page,
            "total_pages": total_pages,
            "page_size": size_num,
            "search_query": clean_q,
            "selected_type": clean_type or "all",
            "selected_status": clean_status or "all",
            "available_types": available_types,
            "prev_page_url": prev_page_url,
            "next_page_url": next_page_url,
            "current_filter_url": current_filter_url,
            "current_user": request.session.get("user", "Analyst")
        }
    )

@router.get("/iocs/{ioc_id}")
def view_ioc(
    request: Request,
    ioc_id: int,
    return_to: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    safe_return_to = None
    if return_to and return_to.startswith("/iocs") and not return_to.startswith("//"):
        safe_return_to = return_to
    else:
        referer = request.headers.get("referer", "")
        if "/iocs" in referer and not referer.startswith("//"):
            try:
                ref_parsed = urlparse(referer)
                if ref_parsed.path.startswith("/iocs") and ref_parsed.path != f"/iocs/{ioc_id}":
                    qs = f"?{ref_parsed.query}" if ref_parsed.query else ""
                    safe_return_to = f"{ref_parsed.path}{qs}"
            except Exception:
                pass
                
    return templates.TemplateResponse(
        request=request,
        name="ioc_detail.html",
        context={
            "request": request,
            "ioc": ioc,
            "return_to": safe_return_to,
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
def toggle_ioc_status(
    request: Request,
    ioc_id: int,
    return_to: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    ioc.is_active = not ioc.is_active
    db.commit()
    
    action = "ioc_activated" if ioc.is_active else "ioc_deactivated"
    log_audit(db, user, action, f"Toggled IOC #{ioc.id} active state to {ioc.is_active}", client_ip)
    
    redirect_url = f"/iocs/{ioc_id}"
    if return_to and return_to.startswith("/iocs") and not return_to.startswith("//"):
        redirect_url += f"?return_to={quote_plus(return_to)}"
        
    return RedirectResponse(url=redirect_url, status_code=303)
