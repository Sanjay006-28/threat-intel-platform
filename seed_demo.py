import os
import sys

# Ensure app is in path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import Base, engine, SessionLocal
from app.collectors.runner import run_all_collectors
from app.models import IOC, IOCSource, Feed, FeedRun, LogFile, LogEvent, Alert, Whitelist
from app.correlator import Correlator
from generate_mock_logs import generate_sample_log_file
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def seed_demo():
    print("[*] Ensuring database tables exist...")
    Base.metadata.create_all(bind=engine)

    
    print("[*] Running feed collectors (this may take a minute)...")
    run_all_collectors()
    
    print("[*] Generating mock log file...")
    log_file_path = generate_sample_log_file("demo_security.log")
    
    print("[*] Processing mock log file...")
    db = SessionLocal()
    
    # Upload simulation
    log_file = LogFile(filename="demo_security.log", type="generic", status="processing")
    db.add(log_file)
    db.commit()
    db.refresh(log_file)
    
    correlator = Correlator(db)
    from app.parsers.manager import process_log_file
    
    line_count = 0
    for log_data in process_log_file(log_file_path):
        line_count += 1
        event = LogEvent(
            log_file_id=log_file.id,
            timestamp=None,
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
    
    print("[+] Seeding complete! You can now run Uvicorn.")

if __name__ == "__main__":
    seed_demo()
