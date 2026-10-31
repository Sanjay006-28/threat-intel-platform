from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import logging
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

def utcnow():
    return datetime.now(timezone.utc)

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

def run_all_collectors():
    """Runs all registered threat feed collectors and updates the IOC database."""
    logger.info("Starting automated threat intelligence collection cycle...")
    db: Session = SessionLocal()
    
    try:
        ttl_delta = timedelta(days=settings.IOC_TTL_DAYS)

        for collector in COLLECTORS:
            # Ensure feed record exists in DB
            feed = db.query(Feed).filter(Feed.name == collector.feed_name).first()
            if not feed:
                feed = Feed(name=collector.feed_name, type="api", enabled=True, interval_minutes=collector.interval_minutes)
                db.add(feed)
                db.commit()
                db.refresh(feed)

            if not feed.enabled:
                continue

            run = FeedRun(feed_id=feed.id, status="processing", start_time=utcnow())
            db.add(run)
            db.commit()
            db.refresh(run)

            try:
                logger.info(f"Fetching threat feed: {collector.feed_name}...")
                raw_data = collector.fetch()
                run.records_fetched = len(raw_data)
                
                normalized = collector.normalize_records(raw_data)
                
                new_count = 0
                updated_count = 0

                # Process records with commit batching
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
                        ioc.last_seen = utcnow()
                        ioc.expires_at = expiry_time
                        ioc.is_active = True
                        ioc.confidence = max(ioc.confidence, rec["confidence"])
                        existing_tags = set(ioc.tags) if ioc.tags else set()
                        new_tags = set(rec["tags"]) if rec["tags"] else set()
                        ioc.tags = list(existing_tags.union(new_tags))
                        updated_count += 1

                    source = db.query(IOCSource).filter(IOCSource.ioc_id == ioc.id, IOCSource.feed_name == collector.feed_name).first()
                    if not source:
                        source = IOCSource(ioc_id=ioc.id, feed_name=collector.feed_name, reference_url=rec.get("reference_url"))
                        db.add(source)
                    else:
                        source.seen_at = utcnow()

                    batch_counter += 1
                    if batch_counter >= 500:
                        db.commit()
                        batch_counter = 0
                        
                db.commit()

                run.status = "success"
                run.end_time = utcnow()
                run.new_records = new_count
                run.updated_records = updated_count
                feed.last_run_status = "success"
                feed.last_run_at = utcnow()
                db.commit()
                
                logger.info(f"[+] {collector.feed_name} complete: {new_count} new, {updated_count} refreshed.")

            except Exception as e:
                logger.error(f"[!] Error running {collector.feed_name}: {e}")
                db.rollback()
                run.status = "failed"
                run.end_time = utcnow()
                run.error_message = str(e)
                feed.last_run_status = "failed"
                feed.last_run_at = utcnow()
                db.commit()

        # Run stale IOC cleanup after collection
        expire_stale_iocs(db)

    finally:
        db.close()
