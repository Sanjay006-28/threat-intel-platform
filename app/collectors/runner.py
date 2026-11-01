import threading
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.config import settings
from app.models import IOC, IOCSource, Feed, FeedRun
from app.collectors.abusech import ThreatFoxCollector, URLhausCollector, FeodoTrackerCollector, MalwareBazaarCollector
from app.collectors.otx import OTXCollector

logger = logging.getLogger(__name__)

COLLECTORS = [
    ThreatFoxCollector(),
    URLhausCollector(),
    FeodoTrackerCollector(),
    MalwareBazaarCollector(),
    OTXCollector()
]

# Concurrency locks and active sync tracking
_SYNC_LOCK = threading.Lock()
_ACTIVE_SYNC_FEEDS = set()

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def is_feed_syncing(feed_id: int) -> bool:
    """Checks whether an individual feed is currently executing a sync task."""
    with _SYNC_LOCK:
        return feed_id in _ACTIVE_SYNC_FEEDS

def is_any_sync_running() -> bool:
    """Checks whether any feed sync operation is currently active."""
    with _SYNC_LOCK:
        return len(_ACTIVE_SYNC_FEEDS) > 0

def recover_stuck_feed_runs(db: Session, max_age_minutes: int = 10) -> int:
    """
    Detects and recovers any orphaned feed runs left in 'processing' state
    due to previous server crashes, worker interruptions, or timeouts.
    Guarantees every run reaches a terminal state without orphaned locks.
    """
    cutoff = utcnow() - timedelta(minutes=max_age_minutes)
    stuck_runs = db.query(FeedRun).filter(
        FeedRun.status == "processing",
        FeedRun.start_time < cutoff
    ).all()
    
    count = len(stuck_runs)
    for run in stuck_runs:
        run.status = "failed"
        run.end_time = utcnow()
        run.error_message = f"Sync abandoned or timed out (stuck in processing state > {max_age_minutes}m; recovered)."
        if run.feed:
            run.feed.last_run_status = "failed"
            run.feed.last_run_at = utcnow()
            
    if count > 0:
        db.commit()
        logger.warning(f"[!] Threat Feed Hub: Recovered {count} stuck feed runs to terminal 'failed' status.")
    return count

def expire_stale_iocs(db: Session = None) -> int:
    """
    Deactivates expired indicators whose TTL has lapsed.
    Preserves historical alerts and incident foreign keys without deleting rows.
    """
    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    try:
        now = utcnow()
        expired_iocs = db.query(IOC).filter(
            IOC.is_active == True,
            IOC.expires_at != None,
            IOC.expires_at < now
        ).all()
        
        count = len(expired_iocs)
        for ioc in expired_iocs:
            ioc.is_active = False
            
        if count > 0:
            db.commit()
            logger.info(f"[+] IOC Lifecycle: Deactivated {count} stale indicators past TTL.")
        return count
    except Exception as e:
        logger.error(f"Error executing IOC expiration cycle: {e}")
        db.rollback()
        return 0
    finally:
        if own_session:
            db.close()

def sync_single_feed(feed_identifier, db: Session = None) -> Dict[str, Any]:
    """
    Synchronizes an individual threat feed connector with concurrency guards,
    strict error boundaries, accurate duplicate counting, and terminal state guarantees.
    feed_identifier can be an int (Feed.id) or str (Feed.name).
    """
    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    try:
        # Resolve feed record
        if isinstance(feed_identifier, int):
            feed = db.query(Feed).filter(Feed.id == feed_identifier).first()
        else:
            feed = db.query(Feed).filter(Feed.name == str(feed_identifier)).first()

        if not feed:
            return {"status": "error", "message": f"Feed '{feed_identifier}' not found in database."}

        # Concurrency check for this specific feed
        with _SYNC_LOCK:
            if feed.id in _ACTIVE_SYNC_FEEDS:
                return {
                    "status": "busy",
                    "feed_name": feed.name,
                    "message": f"Synchronization for feed '{feed.name}' is already actively running."
                }
            _ACTIVE_SYNC_FEEDS.add(feed.id)

        try:
            # Match collector
            collector = next((c for c in COLLECTORS if c.feed_name.lower() == feed.name.lower()), None)
            if not collector:
                return {"status": "error", "message": f"No collector module implemented for '{feed.name}'."}

            # Check if feed is disabled by administrator
            if not feed.enabled:
                return {
                    "status": "disabled",
                    "feed_name": feed.name,
                    "message": f"Feed '{feed.name}' is disabled in configuration."
                }

            # Handle optional unconfigured feeds (e.g. AlienVault OTX without API key)
            if feed.name == "AlienVault_OTX" and (not settings.OTX_API_KEY or "your_otx" in settings.OTX_API_KEY.lower()):
                run = FeedRun(
                    feed_id=feed.id,
                    status="skipped",
                    start_time=utcnow(),
                    end_time=utcnow(),
                    records_fetched=0,
                    new_records=0,
                    updated_records=0,
                    duplicate_records=0,
                    error_message="Optional connector skipped: No OTX_API_KEY configured in .env."
                )
                db.add(run)
                feed.last_run_status = "unconfigured"
                feed.last_run_at = utcnow()
                db.commit()
                return {
                    "status": "skipped",
                    "feed_name": feed.name,
                    "message": "Optional connector skipped: No OTX_API_KEY configured in .env."
                }

            # Start active run
            run = FeedRun(
                feed_id=feed.id,
                status="processing",
                start_time=utcnow(),
                records_fetched=0,
                new_records=0,
                updated_records=0,
                duplicate_records=0
            )
            db.add(run)
            feed.last_run_status = "processing"
            feed.last_run_at = utcnow()
            db.commit()
            db.refresh(run)

            # Fetch data from upstream API / source
            logger.info(f"[*] Synchronizing threat feed: {feed.name}...")
            try:
                raw_data = collector.fetch()
            except Exception as fetch_err:
                run.status = "failed"
                run.end_time = utcnow()
                run.error_message = f"Upstream API failure: {fetch_err}"
                feed.last_run_status = "failed"
                feed.last_run_at = utcnow()
                db.commit()
                return {
                    "status": "failed",
                    "feed_name": feed.name,
                    "message": str(fetch_err)
                }

            records_fetched = len(raw_data)
            run.records_fetched = records_fetched

            # Normalize records
            normalized = collector.normalize_records(raw_data)
            feed_dupes_count = records_fetched - len(normalized)

            ttl_delta = timedelta(days=settings.IOC_TTL_DAYS)
            new_count = 0
            updated_count = 0
            db_dupes_count = 0
            batch_counter = 0

            for rec in normalized:
                expiry_time = utcnow() + ttl_delta
                ioc = db.query(IOC).filter(IOC.value == rec["value"], IOC.type == rec["type"]).first()

                if not ioc:
                    ioc = IOC(
                        type=rec["type"],
                        value=rec["value"],
                        confidence=rec["confidence"],
                        severity="high" if rec["confidence"] >= 75 else "medium",
                        tags=rec["tags"],
                        description=rec["description"],
                        first_seen=utcnow(),
                        last_seen=utcnow(),
                        expires_at=expiry_time,
                        is_active=True
                    )
                    db.add(ioc)
                    db.flush()
                    new_count += 1
                else:
                    changed = False
                    if not ioc.is_active:
                        ioc.is_active = True
                        changed = True
                    if rec["confidence"] > ioc.confidence:
                        ioc.confidence = rec["confidence"]
                        changed = True
                    existing_tags = set(ioc.tags) if ioc.tags else set()
                    new_tags = set(rec["tags"]) if rec["tags"] else set()
                    if not new_tags.issubset(existing_tags):
                        ioc.tags = list(existing_tags.union(new_tags))
                        changed = True

                    ioc.last_seen = utcnow()
                    ioc.expires_at = expiry_time

                    if changed:
                        updated_count += 1
                    else:
                        db_dupes_count += 1

                # Attribution source tracking
                source = db.query(IOCSource).filter(IOCSource.ioc_id == ioc.id, IOCSource.feed_name == feed.name).first()
                if not source:
                    source = IOCSource(ioc_id=ioc.id, feed_name=feed.name, reference_url=rec.get("reference_url"))
                    db.add(source)
                else:
                    source.seen_at = utcnow()

                batch_counter += 1
                if batch_counter >= 500:
                    db.commit()
                    batch_counter = 0

            db.commit()

            total_dupes = feed_dupes_count + db_dupes_count
            end_time = utcnow()
            
            run.status = "success"
            run.end_time = end_time
            run.new_records = new_count
            run.updated_records = updated_count
            run.duplicate_records = total_dupes
            run.error_message = None

            feed.last_run_status = "success"
            feed.last_run_at = end_time
            feed.last_successful_sync = end_time
            db.commit()

            logger.info(f"[+] {feed.name} sync successful: {records_fetched} fetched, {new_count} new, {updated_count} refreshed, {total_dupes} duplicate.")
            return {
                "status": "success",
                "feed_name": feed.name,
                "records_fetched": records_fetched,
                "new_records": new_count,
                "updated_records": updated_count,
                "duplicate_records": total_dupes
            }

        finally:
            with _SYNC_LOCK:
                _ACTIVE_SYNC_FEEDS.discard(feed.id)

    except Exception as general_err:
        logger.error(f"[!] Unhandled exception syncing feed '{feed_identifier}': {general_err}")
        db.rollback()
        try:
            # Ensure feed and run reach a terminal failure state
            feed_obj = db.query(Feed).filter(
                (Feed.id == feed_identifier) if isinstance(feed_identifier, int) else (Feed.name == str(feed_identifier))
            ).first()
            if feed_obj:
                feed_obj.last_run_status = "failed"
                feed_obj.last_run_at = utcnow()
                # Find current running FeedRun if exists
                active_run = db.query(FeedRun).filter(FeedRun.feed_id == feed_obj.id, FeedRun.status == "processing").order_by(FeedRun.id.desc()).first()
                if active_run:
                    active_run.status = "failed"
                    active_run.end_time = utcnow()
                    active_run.error_message = str(general_err)
                db.commit()
        except Exception:
            pass
        return {"status": "failed", "feed_name": str(feed_identifier), "message": str(general_err)}

    finally:
        if own_session:
            db.close()

def run_all_collectors(db: Session = None) -> Dict[str, Any]:
    """
    Runs all registered threat feed collectors sequentially.
    Ensures feed failure isolation: a failure in one feed never blocks remaining feeds.
    Recovers any stuck jobs and triggers post-sync IOC expiration.
    """
    logger.info("Starting automated threat intelligence collection cycle...")
    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    try:
        # 1. Recover any abandoned runs from previous interruptions
        recover_stuck_feed_runs(db)

        # 2. Ensure all feed entities exist in database
        for collector in COLLECTORS:
            feed = db.query(Feed).filter(Feed.name == collector.feed_name).first()
            if not feed:
                feed = Feed(
                    name=collector.feed_name,
                    type="api",
                    enabled=True,
                    interval_minutes=collector.interval_minutes
                )
                db.add(feed)
                db.commit()
                db.refresh(feed)

        # 3. Synchronize each collector independently
        results = []
        for collector in COLLECTORS:
            res = sync_single_feed(collector.feed_name, db=db)
            results.append(res)

        # 4. Run stale IOC expiration
        expire_stale_iocs(db)

        total_new = sum(r.get("new_records", 0) for r in results)
        total_updated = sum(r.get("updated_records", 0) for r in results)
        total_fetched = sum(r.get("records_fetched", 0) for r in results)
        success_count = sum(1 for r in results if r.get("status") == "success")
        failed_count = sum(1 for r in results if r.get("status") == "failed")
        skipped_count = sum(1 for r in results if r.get("status") == "skipped")

        logger.info(f"[+] Threat Feed Cycle complete: {success_count} success, {failed_count} failed, {skipped_count} skipped. ({total_new} new IOCs)")
        return {
            "total_feeds": len(COLLECTORS),
            "success": success_count,
            "failed": failed_count,
            "skipped": skipped_count,
            "records_fetched": total_fetched,
            "new_records": total_new,
            "updated_records": total_updated,
            "results": results
        }
    finally:
        if own_session:
            db.close()
