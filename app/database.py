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
        except Exception as e:
            logger.debug(f"Alerts schema migration notice: {e}")

        # Check whitelist table columns
        try:
            wl_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(whitelist)")).fetchall()]
            if "reason" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN reason VARCHAR(255)"))
            if "created_at" not in wl_cols:
                conn.execute(text("ALTER TABLE whitelist ADD COLUMN created_at DATETIME"))
            conn.commit()
        except Exception as e:
            logger.debug(f"Whitelist schema migration notice: {e}")
