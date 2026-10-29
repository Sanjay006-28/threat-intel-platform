from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import IOC

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/iocs")
def list_iocs(request: Request, db: Session = Depends(get_db)):
    iocs = db.query(IOC).order_by(IOC.id.desc()).limit(100).all()
    return templates.TemplateResponse(request=request, name="iocs.html", context={"request": request, "iocs": iocs})
