import os
import sys

# Ensure project root and scripts directory are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if os.path.dirname(__file__) not in sys.path:
    sys.path.insert(0, os.path.dirname(__file__))

from app.database import Base, engine, SessionLocal
from app.collectors.runner import run_all_collectors
from app.models import IOC, IOCSource, Feed, FeedRun, LogFile, LogEvent, Alert, Whitelist
from app.correlator import Correlator
from scripts.generate_mock_logs import generate_sample_log_file
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def seed_demo():
    print("[*] Ensuring database tables exist...")
    Base.metadata.create_all(bind=engine)

    
    print("[*] Running feed collectors (this may take a minute)...")
    run_all_collectors()
    
    print("[*] Generating mock log file...")
    demo_log_dir = os.path.join(BASE_DIR, "demo_logs")
    os.makedirs(demo_log_dir, exist_ok=True)
    log_file_path = generate_sample_log_file(os.path.join(demo_log_dir, "demo_security.log"))
    
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
