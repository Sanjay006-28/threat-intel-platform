import os
import shutil
import logging
from fastapi import APIRouter, Request, Depends, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import LogFile, LogEvent
from app.parsers.manager import process_log_file
from app.correlator import Correlator
from app.config import settings
from app.audit import log_audit

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def ingest_and_correlate_stream(db: Session, log_file: LogFile, file_path: str, batch_size: int = None) -> int:
    """
    Streams and correlates log files in controlled transactional batches.
    Prevents database freezing and out-of-memory errors on large log streams.
    """
    batch_limit = batch_size or settings.BATCH_SIZE
    correlator = Correlator(db)
    line_count = 0
    batch = []
    
    try:
        for log_data in process_log_file(file_path):
            line_count += 1
            event = LogEvent(
                log_file_id=log_file.id,
                timestamp=log_data["timestamp"],
                raw_line=log_data["raw_line"],
                extracted_artifacts=log_data["artifacts"]
            )
            batch.append(event)
            
            if len(batch) >= batch_limit:
                db.add_all(batch)
                db.flush()
                for ev in batch:
                    correlator.correlate_event(ev)
                db.commit()
                batch.clear()
                
        # Final remaining batch
        if batch:
            db.add_all(batch)
            db.flush()
            for ev in batch:
                correlator.correlate_event(ev)
            db.commit()
            batch.clear()

        log_file.line_count = line_count
        log_file.status = "done"
        db.commit()
        return line_count

    except Exception as e:
        logger.error(f"Error during log ingestion batch processing for {file_path}: {e}")
        db.rollback()
        log_file.status = "error"
        db.commit()
        raise

@router.get("/logs")
def list_logs(request: Request, db: Session = Depends(get_db)):
    logs = db.query(LogFile).order_by(LogFile.id.desc()).limit(25).all()
    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={"request": request, "logs": logs, "current_user": request.session.get("user", "Analyst")}
    )

@router.post("/logs/run-demo")
def run_demo_log(request: Request, db: Session = Depends(get_db)):
    """Runs the built-in demo_security.log file with batch processing."""
    demo_file = "demo_security.log"
    if not os.path.exists(demo_file):
        return RedirectResponse(url="/logs", status_code=303)

    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    log_file = LogFile(filename="demo_security.log", type="demo_sample", status="processing")
    db.add(log_file)
    db.commit()
    db.refresh(log_file)

    line_count = ingest_and_correlate_stream(db, log_file, demo_file)
    log_audit(db, user, "demo_log_processed", f"Processed demo security log ({line_count} events)", client_ip)

    return RedirectResponse(url="/alerts", status_code=303)

@router.post("/logs/upload")
async def upload_log(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename:
        return RedirectResponse(url="/logs", status_code=303)

    user = request.session.get("user", "Analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"
        
    os.makedirs("uploads", exist_ok=True)
    # Sanitize filename
    clean_filename = os.path.basename(file.filename)
    file_path = os.path.join("uploads", clean_filename)
    
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
        
    log_file = LogFile(filename=clean_filename, type="manual_upload", status="processing")
    db.add(log_file)
    db.commit()
    db.refresh(log_file)
    
    try:
        line_count = ingest_and_correlate_stream(db, log_file, file_path)
        log_audit(db, user, "log_file_uploaded", f"Ingested {clean_filename} ({line_count} events)", client_ip)
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        
    return RedirectResponse(url="/alerts", status_code=303)
