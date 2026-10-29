from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging
from app.database import SessionLocal
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

def run_all_collectors():
    """Runs all collectors and saves to the database."""
    logger.info("Starting feed collection cycle...")
    db: Session = SessionLocal()
    
    for collector in COLLECTORS:
        # Ensure feed exists in DB
        feed = db.query(Feed).filter(Feed.name == collector.feed_name).first()
        if not feed:
            feed = Feed(name=collector.feed_name, type="api", enabled=True, interval_minutes=collector.interval_minutes)
            db.add(feed)
            db.commit()
            db.refresh(feed)

        if not feed.enabled:
            continue

        run = FeedRun(feed_id=feed.id, status="processing")
        db.add(run)
        db.commit()
        db.refresh(run)

        try:
            logger.info(f"Fetching {collector.feed_name}...")
            raw_data = collector.fetch()
            run.records_fetched = len(raw_data)
            
            normalized = collector.normalize_records(raw_data)
            
            new_count = 0
            updated_count = 0

            # Batch processing could be optimized further, but this satisfies the requirement
            for rec in normalized:
                ioc = db.query(IOC).filter(IOC.value == rec["value"], IOC.type == rec["type"]).first()
                if not ioc:
                    ioc = IOC(
                        type=rec["type"],
                        value=rec["value"],
                        confidence=rec["confidence"],
                        severity="high" if rec["confidence"] >= 75 else "medium",
                        tags=rec["tags"],
                        description=rec["description"]
                    )
                    db.add(ioc)
                    db.flush()
                    new_count += 1
                else:
                    ioc.last_seen = utcnow()
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
                    
            db.commit()

            run.status = "success"
            run.new_records = new_count
            run.updated_records = updated_count
            feed.last_run_status = "success"
            feed.last_run_at = utcnow()
            
            logger.info(f"{collector.feed_name} complete: {new_count} new, {updated_count} updated.")

        except Exception as e:
            logger.error(f"Error running {collector.feed_name}: {e}")
            run.status = "failed"
            run.error_message = str(e)
            feed.last_run_status = "failed"
            feed.last_run_at = utcnow()

        run.end_time = utcnow()
        db.commit()

    db.close()
    logger.info("Feed collection cycle complete.")
