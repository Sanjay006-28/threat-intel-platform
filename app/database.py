import logging
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False, "timeout": 30}
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configures SQLite connection for high concurrency, WAL mode and timeout."""
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=15000")
        cursor.close()
    except Exception as e:
        logger.debug(f"SQLite PRAGMA setup warning: {e}")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def apply_schema_migrations(eng):
    """
    Safely creates any newly defined tables and applies backwards-compatible column additions
    to preserve existing database records.
    """
    # Create any missing tables (e.g. audit_logs, incidents)
    Base.metadata.create_all(bind=eng)

    with eng.connect() as conn:
        # Check alerts table columns
        try:
            alerts_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(alerts)")).fetchall()]
            if "first_seen" not in alerts_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN first_seen DATETIME"))
            if "last_seen" not in alerts_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN last_seen DATETIME"))
            if "hit_count" not in alerts_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN hit_count INTEGER DEFAULT 1"))
            if "incident_id" not in alerts_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN incident_id INTEGER REFERENCES incidents(id)"))
            conn.commit()

            # Reconcile legacy unbounded scores (e.g. 109 -> 100) and backfill timestamps
            conn.execute(text("UPDATE alerts SET score = 100 WHERE score > 100"))
            conn.execute(text("UPDATE alerts SET score = 0 WHERE score < 0"))
            conn.execute(text("UPDATE alerts SET first_seen = created_at WHERE first_seen IS NULL AND created_at IS NOT NULL"))
            conn.execute(text("UPDATE alerts SET last_seen = created_at WHERE last_seen IS NULL AND created_at IS NOT NULL"))
            conn.commit()
        except Exception as e:
            logger.debug(f"Alerts schema migration notice: {e}")

        # Check whitelist table columns
        try:
            wl_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(whitelist)")).fetchall()]
            if "reason" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN reason VARCHAR(255)"))
            if "created_at" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN created_at DATETIME"))
            if "is_active" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN is_active BOOLEAN DEFAULT 1 NOT NULL"))
            if "is_deleted" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN is_deleted BOOLEAN DEFAULT 0 NOT NULL"))
            if "created_by" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN created_by VARCHAR(100) DEFAULT 'system'"))
            if "updated_at" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN updated_at DATETIME"))
            if "expires_at" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN expires_at DATETIME"))
            conn.commit()
        except Exception as e:
            logger.debug(f"Whitelist schema migration notice: {e}")

        # Check incidents table columns for soft deletion support
        try:
            inc_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(incidents)")).fetchall()]
            if "is_deleted" not in inc_cols:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN is_deleted BOOLEAN DEFAULT 0 NOT NULL"))
            if "deleted_at" not in inc_cols:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN deleted_at DATETIME"))
            if "deleted_by" not in inc_cols:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN deleted_by VARCHAR(100)"))
            conn.commit()
        except Exception as e:
            logger.debug(f"Incidents schema migration notice: {e}")

        # Check feeds table columns for last_successful_sync
        try:
            feed_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(feeds)")).fetchall()]
            if "last_successful_sync" not in feed_cols:
                conn.execute(text("ALTER TABLE feeds ADD COLUMN last_successful_sync DATETIME"))
                conn.commit()
            
            # Backfill last_successful_sync from historical successful feed_runs if null
            conn.execute(text("""
                UPDATE feeds 
                SET last_successful_sync = (
                    SELECT MAX(end_time) FROM feed_runs 
                    WHERE feed_runs.feed_id = feeds.id AND feed_runs.status = 'success'
                )
                WHERE last_successful_sync IS NULL
            """))
            conn.commit()
        except Exception as e:
            logger.debug(f"Feeds schema migration notice: {e}")

        # Check feed_runs table columns for duplicate_records
        try:
            run_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(feed_runs)")).fetchall()]
            if "duplicate_records" not in run_cols:
                conn.execute(text("ALTER TABLE feed_runs ADD COLUMN duplicate_records INTEGER DEFAULT 0"))
                conn.commit()
        except Exception as e:
            logger.debug(f"FeedRuns schema migration notice: {e}")
