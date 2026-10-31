import os
import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.config import settings
from app.database import SessionLocal
from app.models import LogFile
from app.routes.logs import ingest_and_correlate_stream

logger = logging.getLogger(__name__)

def wait_until_file_ready(file_path: str, max_wait: float = 8.0, check_interval: float = 0.5) -> bool:
    """
    Waits until a file has finished writing by verifying size stability and exclusive read access.
    Avoids partial ingestion bugs caused by fixed blind delays.
    """
    start_time = time.time()
    last_size = -1
    
    while time.time() - start_time < max_wait:
        if not os.path.exists(file_path):
            return False
        try:
            current_size = os.path.getsize(file_path)
            if current_size == last_size and current_size > 0:
                # Test opening file for reading to ensure write handle is released
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    _ = f.read(512)
                return True
            last_size = current_size
        except (OSError, PermissionError):
            pass
        time.sleep(check_interval)
        
    return os.path.exists(file_path) and os.path.getsize(file_path) > 0

class LogDropHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = str(event.src_path)
        self.process_candidate(file_path)

    def process_candidate(self, file_path: str):
        valid_exts = (".log", ".txt", ".json")
        if not file_path.endswith(valid_exts) or file_path.endswith(".processed"):
            return

        # Ensure file write has completed
        if not wait_until_file_ready(file_path):
            logger.warning(f"File {file_path} did not settle in time for auto-ingestion.")
            return

        self._process_file_with_retries(file_path)

    def _process_file_with_retries(self, file_path: str, max_retries: int = 3):
        retries = 0
        while retries < max_retries:
            try:
                self._process_file(file_path)
                return
            except (OSError, PermissionError) as e:
                retries += 1
                logger.warning(f"File lock on {file_path} (attempt {retries}/{max_retries}): {e}")
                time.sleep(1.0)
            except Exception as e:
                logger.error(f"Unrecoverable error processing {file_path}: {e}")
                return

    def _process_file(self, file_path: str):
        if not os.path.exists(file_path) or file_path.endswith(".processed"):
            return

        logger.info(f"[*] Auto-ingesting security log file: {file_path}")
        db = SessionLocal()
        try:
            filename = Path(file_path).name
            log_entry = LogFile(filename=f"auto_{filename}", type="auto_ingest", status="processing")
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            # High-performance batch stream correlation
            line_count = ingest_and_correlate_stream(db, log_entry, file_path)
            logger.info(f"[+] Auto-ingest completed: {filename} ({line_count} events).")

            # Rename safely to prevent re-ingestion
            processed_name = f"{file_path}.processed"
            counter = 1
            while os.path.exists(processed_name):
                processed_name = f"{file_path}.{counter}.processed"
                counter += 1
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
        self.handler = LogDropHandler()

    def recover_pending_files(self):
        """Scans auto_ingest folder on startup to recover any unprocessed files after restart."""
        db = SessionLocal()
        try:
            # Mark any stalled jobs as interrupted
            stalled = db.query(LogFile).filter(LogFile.status == "processing").all()
            for s in stalled:
                s.status = "interrupted_recovered"
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        # Ingest any pending un-processed files dropped while server was offline
        if os.path.exists(self.watch_dir):
            for entry in os.scandir(self.watch_dir):
                if entry.is_file() and not entry.name.endswith(".processed"):
                    if entry.name.endswith((".log", ".txt", ".json")):
                        logger.info(f"[*] Recovering offline dropped log file: {entry.path}")
                        self.handler.process_candidate(entry.path)

    def start(self):
        os.makedirs(self.watch_dir, exist_ok=True)
        self.recover_pending_files()
        
        self.observer = Observer()
        self.observer.schedule(self.handler, self.watch_dir, recursive=False)
        self.observer.daemon = True
        self.observer.start()
        logger.info(f"[+] Directory watcher active on {self.watch_dir}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            logger.info("[*] Directory watcher stopped cleanly.")
