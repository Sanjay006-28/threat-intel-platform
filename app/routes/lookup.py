from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import IOC, Alert

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/lookup")
def lookup_page(request: Request):
    return templates.TemplateResponse(request=request, name="lookup.html", context={"request": request})

@router.post("/lookup")
def perform_lookup(request: Request, query: str = Form(...), db: Session = Depends(get_db)):
    query = query.strip().lower()
    from sqlalchemy import or_
    
    # Simple search in value or description
    iocs = db.query(IOC).filter(
        or_(
            IOC.value.like(f"%{query}%"),
            IOC.description.like(f"%{query}%")
        )
    ).all()
    
    # Alerts matching the query
    alerts = db.query(Alert).filter(Alert.matched_value.like(f"%{query}%")).all()
    
    return templates.TemplateResponse(request=request, name="lookup.html", context={
        "request": request, 
        "query": query, 
        "iocs": iocs, 
        "alerts": alerts
    })
