"""
scheduler.py
Background thread that auto-syncs threat feeds every N hours.
Imported and started by app.py on Streamlit launch.
"""

import threading
import time
import schedule
from datetime import datetime
from feed_collector import run_all_collectors

# Sync interval in hours
SYNC_INTERVAL_HOURS = 6

# Last sync result (readable from UI)
_last_sync_result: dict  = {}
_last_sync_time: str     = "Never"
_lock = threading.Lock()


def _sync_job():
    global _last_sync_result, _last_sync_time
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [Scheduler] Running threat feed sync…")
    result = run_all_collectors()
    with _lock:
        _last_sync_result = result
        _last_sync_time   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(result.values())
    print(f"[Scheduler] Sync done. New IOCs: {total}")


def get_last_sync_info() -> dict:
    """Returns the last sync result dict and timestamp (thread-safe)."""
    with _lock:
        return {
            "time":   _last_sync_time,
            "counts": dict(_last_sync_result),
        }


def start_scheduler():
    """
    Starts a daemon background thread that syncs feeds every SYNC_INTERVAL_HOURS.
    Safe to call multiple times — uses a module-level flag to avoid double-starting.
    """
    if getattr(start_scheduler, "_started", False):
        return
    start_scheduler._started = True

    # Run once immediately in background so IOCs are populated on first launch
    threading.Thread(target=_sync_job, daemon=True, name="InitialSync").start()

    # Schedule recurring syncs
    schedule.every(SYNC_INTERVAL_HOURS).hours.do(_sync_job)

    def _runner():
        while True:
            schedule.run_pending()
            time.sleep(60)

    t = threading.Thread(target=_runner, daemon=True, name="FeedScheduler")
    t.start()
    print(f"[Scheduler] Started — feeds will sync every {SYNC_INTERVAL_HOURS} hours.")
