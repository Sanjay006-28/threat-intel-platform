import os
from fastapi import APIRouter, Request, Depends, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import LogFile, LogEvent
from app.parsers.manager import process_log_file
from app.correlator import Correlator

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/logs")
def list_logs(request: Request, db: Session = Depends(get_db)):
    logs = db.query(LogFile).order_by(LogFile.id.desc()).limit(20).all()
    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={"request": request, "logs": logs}
    )

@router.post("/logs/run-demo")
def run_demo_log(request: Request, db: Session = Depends(get_db)):
    """Runs the built-in demo_security.log file with 1-click and redirects to alerts."""
    demo_file = "demo_security.log"
    if not os.path.exists(demo_file):
        return RedirectResponse(url="/logs", status_code=303)

    log_file = LogFile(filename="demo_security.log", type="demo_sample", status="processing")
    db.add(log_file)
    db.commit()
    db.refresh(log_file)

    correlator = Correlator(db)
    line_count = 0
    
    for log_data in process_log_file(demo_file):
        line_count += 1
        event = LogEvent(
            log_file_id=log_file.id,
            raw_line=log_data["raw_line"],
            extracted_artifacts=log_data["artifacts"]
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        correlator.correlate_event(event)

    log_file.line_count = line_count
    log_file.status = "done"
    db.commit()

    return RedirectResponse(url="/alerts", status_code=303)

@router.post("/logs/upload")
async def upload_log(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename:
        return RedirectResponse(url="/logs", status_code=303)
        
    os.makedirs("uploads", exist_ok=True)
    file_path = f"uploads/{file.filename}"
    with open(file_path, "wb") as f:
        f.write(await file.read())
        
    log_file = LogFile(filename=file.filename, type="manual_upload", status="processing")
    db.add(log_file)
    db.commit()
    db.refresh(log_file)
    
    correlator = Correlator(db)
    line_count = 0
    
    for log_data in process_log_file(file_path):
        line_count += 1
        event = LogEvent(
            log_file_id=log_file.id,
            raw_line=log_data["raw_line"],
            extracted_artifacts=log_data["artifacts"]
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        
        correlator.correlate_event(event)

    log_file.line_count = line_count
    log_file.status = "done"
    db.commit()
    
    try:
        os.remove(file_path)
    except:
        pass
        
    return RedirectResponse(url="/alerts", status_code=303)
