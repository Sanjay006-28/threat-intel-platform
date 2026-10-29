import os
import time
import logging
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app.config import settings
from app.database import SessionLocal
from app.models import LogFile, LogEvent
from app.parsers.manager import process_log_file
from app.correlator import Correlator

logger = logging.getLogger(__name__)

class LogDropHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if file_path.endswith(".log") or file_path.endswith(".txt") or file_path.endswith(".json"):
            # Wait briefly to ensure file write finishes
            time.sleep(1.0)
            self._process_file(file_path)

    def _process_file(self, file_path: str):
        if file_path.endswith(".processed"):
            return

        logger.info(f"[*] Auto-ingesting new log file: {file_path}")
        db = SessionLocal()
        try:
            filename = Path(file_path).name
            log_entry = LogFile(filename=f"auto_{filename}", type="auto_ingest", status="processing")
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            correlator = Correlator(db)
            line_count = 0
            alert_count = 0

            for parsed_data in process_log_file(file_path):
                line_count += 1
                ev = LogEvent(
                    log_file_id=log_entry.id,
                    raw_line=parsed_data["raw_line"],
                    extracted_artifacts=parsed_data["artifacts"]
                )
                db.add(ev)
                db.commit()
                db.refresh(ev)

                alerts = correlator.correlate_event(ev)
                alert_count += len(alerts)

            log_entry.line_count = line_count
            log_entry.status = "done"
            db.commit()

            logger.info(f"[+] Auto-ingest completed: {filename} ({line_count} lines, {alert_count} alerts).")

            # Rename to avoid reprocessing
            processed_name = f"{file_path}.processed"
            if not os.path.exists(processed_name):
                os.rename(file_path, processed_name)

        except Exception as e:
            logger.error(f"[!] Auto-ingestion error for {file_path}: {e}")
            db.rollback()
        finally:
            db.close()

class AutoIngestWatcher:
    def __init__(self, watch_dir: str = None):
        self.watch_dir = watch_dir or settings.AUTO_INGEST_DIR
        self.observer = None
        self.thread = None

    def start(self):
        os.makedirs(self.watch_dir, exist_ok=True)
        event_handler = LogDropHandler()
        self.observer = Observer()
        self.observer.schedule(event_handler, self.watch_dir, recursive=False)
        self.observer.daemon = True
        self.observer.start()
        logger.info(f"[+] Directory watcher active on {self.watch_dir}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("[*] Directory watcher stopped.")
